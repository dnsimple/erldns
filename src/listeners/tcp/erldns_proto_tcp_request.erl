-module(erldns_proto_tcp_request).
-moduledoc false.

-include_lib("kernel/include/logger.hrl").
-include_lib("dns_erlang/include/dns.hrl").

-define(MIN_HEAP_SIZE, 650).

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
    SpawnOpts = [link, {min_heap_size, ?MIN_HEAP_SIZE}],
    Params = [RequestBinary, TS0, Socket, SocketType, IpAddr, Port],
    proc_lib:spawn_opt(?MODULE, request, Params, SpawnOpts).

-spec request(
    dns:message_bin(),
    erldns_proto_tcp:ts(),
    erldns_proto_tcp:socket(),
    erldns_proto_tcp:socket_type(),
    inet:ip_address(),
    inet:port_number()
) -> term().
request(RequestBinary, TS0, Socket, SocketType, IpAddr, Port) ->
    proc_lib:set_label({?MODULE, Port}),
    Measurements = #{monotonic_time => TS0, request_size => byte_size(RequestBinary)},
    InitMetadata = #{transport => tcp},
    telemetry:execute([erldns, request, start], Measurements, InitMetadata),
    Decoded = dns:decode_query(RequestBinary),
    handle_decoded(Decoded, TS0, Socket, SocketType, IpAddr, Port).

-spec handle_decoded(
    {dns:decode_error(), dns:message() | undefined, binary()} | dns:message(),
    erldns_proto_tcp:ts(),
    erldns_proto_tcp:socket(),
    erldns_proto_tcp:socket_type(),
    inet:ip_address(),
    inet:port_number()
) ->
    atom().
handle_decoded(#dns_message{} = Msg, TS0, Socket, SocketType, IpAddr, Port) ->
    InitOpts = #{
        monotonic_time => TS0,
        transport => tcp,
        socket => Socket,
        host => IpAddr,
        port => Port
    },
    Response = erldns_pipeline:call(Msg, InitOpts),
    handle_pipeline_response(Response, TS0, Socket, SocketType);
handle_decoded({notimp, #dns_message{} = Msg, _}, TS0, Socket, SocketType, _, _) ->
    Metadata = #{transport => tcp, reason => notimp, message => Msg, monotonic_time => TS0},
    request_error_event(Metadata),
    handle_pipeline_response(Msg, TS0, Socket, SocketType);
handle_decoded({Error, Msg, _}, TS0, _, _, _, _) ->
    Metadata = #{transport => tcp, reason => Error, message => Msg, monotonic_time => TS0},
    request_error_event(Metadata).

-spec handle_pipeline_response(PipeResult, TS, Socket, SocketType) -> ok when
    PipeResult :: erldns_pipeline:result() | erldns_pipeline:continuation(),
    TS :: erldns_proto_tcp:ts(),
    Socket :: erldns_proto_tcp:socket(),
    SocketType :: erldns_proto_tcp:socket_type().
handle_pipeline_response(halt, _, _, _) ->
    ok;
handle_pipeline_response(#dns_message{} = Response, TS0, Socket, SocketType) ->
    EncodedResponse = erldns_encoder:encode_message(Response),
    Payload = [<<(byte_size(EncodedResponse)):16>>, EncodedResponse],
    ok = send_data(Socket, SocketType, Payload),
    measure_time(Response, TS0, EncodedResponse);
handle_pipeline_response({suspend, Continuation}, TS0, Socket, SocketType) ->
    Executed = erldns_pipeline:execute_work(Continuation),
    handle_pipeline_response(Executed, TS0, Socket, SocketType);
handle_pipeline_response(Continuation, TS0, Socket, SocketType) ->
    FinalResponse = erldns_pipeline:resume_pipeline(Continuation),
    handle_pipeline_response(FinalResponse, TS0, Socket, SocketType).

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
