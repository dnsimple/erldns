-module(erldns_proto_tcp_request).
-moduledoc false.

-include_lib("kernel/include/logger.hrl").
-include_lib("dns_erlang/include/dns.hrl").

-export([start_link/6]).
-export([request/6]).

-spec start_link(
    dns:message_bin(),
    erldns_proto_tcp:ts(),
    erldns_proto_tcp:socket(),
    erldns_proto_tcp:socket_type(),
    inet:ip_address(),
    inet:port_number()
) ->
    pid().
start_link(RequestBinary, TS0, Socket, SocketType, IpAddr, Port) ->
    SpawnOpts = [link, {min_heap_size, 500}],
    Params = [RequestBinary, TS0, Socket, SocketType, IpAddr, Port],
    proc_lib:spawn_opt(?MODULE, request, Params, SpawnOpts).

-spec request(
    dns:message_bin(),
    erldns_proto_tcp:ts(),
    erldns_proto_tcp:socket(),
    erldns_proto_tcp:socket_type(),
    inet:ip_address(),
    inet:port_number()
) -> no_return().
request(RequestBinary, TS0, Socket, SocketType, IpAddr, Port) ->
    proc_lib:set_label({?MODULE, Port}),
    Measurements = #{monotonic_time => TS0, request_size => byte_size(RequestBinary)},
    InitMetadata = #{transport => tcp},
    telemetry:execute([erldns, request, start], Measurements, InitMetadata),
    Decoded = dns:decode_message(RequestBinary),
    handle_decoded(Decoded, TS0, Socket, SocketType, IpAddr, Port).

-spec handle_decoded(
    dns:message(),
    erldns_proto_tcp:ts(),
    erldns_proto_tcp:socket(),
    erldns_proto_tcp:socket_type(),
    inet:ip_address(),
    inet:port_number()
) ->
    atom().
handle_decoded(#dns_message{qr = false} = Msg, TS0, Socket, SocketType, IpAddr, Port) ->
    InitOpts = #{
        monotonic_time => TS0,
        transport => tcp,
        socket => Socket,
        host => IpAddr,
        port => Port
    },
    Response = erldns_pipeline:call(Msg, InitOpts),
    handle_pipeline_response(Response, TS0, Socket, SocketType);
handle_decoded(#dns_message{qr = true}, _, _, _, _, _) ->
    not_a_question;
handle_decoded({Error, Message, _}, _, _, _, _, _) ->
    ErrorMetadata = #{transport => tcp, reason => Error, message => Message},
    request_error_event(ErrorMetadata).

-spec handle_pipeline_response(
    halt | dns:message(),
    erldns_proto_tcp:ts(),
    erldns_proto_tcp:socket(),
    erldns_proto_tcp:socket_type()
) ->
    ok.
handle_pipeline_response(halt, _, _, _) ->
    ok;
handle_pipeline_response(#dns_message{} = Response, TS0, Socket, SocketType) ->
    EncodedResponse = erldns_encoder:encode_message(Response),
    Payload = [<<(byte_size(EncodedResponse)):16>>, EncodedResponse],
    ok = send_data(Socket, SocketType, Payload),
    measure_time(Response, TS0, EncodedResponse).

-spec send_data(erldns_proto_tcp:socket(), erldns_proto_tcp:socket_type(), iodata()) ->
    ok | {error, term()}.
send_data(Socket, tcp, Data) ->
    gen_tcp:send(Socket, Data);
send_data(Socket, ssl, Data) ->
    ssl:send(Socket, Data).

-spec request_error_event(map()) -> ok.
request_error_event(Metadata) ->
    telemetry:execute([erldns, request, error], #{count => 1}, Metadata).

-spec measure_time(dns:message(), erldns_proto_tcp:ts(), binary()) -> ok.
measure_time(Response, TS0, EncodedResponse) ->
    ?LOG_DEBUG(
        #{what => tcp_request_finished, dns_message => Response},
        #{domain => [erldns, listeners]}
    ),
    TS1 = erlang:monotonic_time(),
    Measurements = #{
        monotonic_time => TS1,
        duration => TS1 - TS0,
        response_size => byte_size(EncodedResponse)
    },
    DnsSec = proplists:get_bool(dnssec, erldns_edns:get_opts(Response)),
    Metadata = #{
        transport => tcp,
        dnssec => DnsSec,
        dns_message => Response
    },
    telemetry:execute([erldns, request, stop], Measurements, Metadata).
