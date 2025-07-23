-module(erldns_proto_tcp).
-moduledoc false.

-include_lib("kernel/include/logger.hrl").
-include_lib("dns_erlang/include/dns.hrl").

-compile({inline, [maybe_receive_params/0, forward_dp_to_timer/2, get_dnssec/1, get_query/1]}).

-behaviour(ranch_protocol).
-export([start_link/3]).
-export([init/2]).
-export([init_timer/2]).

-spec start_link(ranch:ref(), module(), non_neg_integer()) -> dynamic().
start_link(Ref, _Transport, IngressTimeoutMs) ->
    SpawnOpts = [{min_heap_size, 500}],
    proc_lib:start_link(?MODULE, init, [Ref, IngressTimeoutMs], 5000, SpawnOpts).

-spec init(ranch:ref(), non_neg_integer()) -> dynamic().
init(Ref, IngressTimeoutMs) ->
    Self = self(),
    proc_lib:init_ack({ok, Self}),
    proc_lib:set_label(?MODULE),
    TS = erlang:monotonic_time(),
    TimerArgs = [IngressTimeoutMs, Self],
    TimerOpts = [monitor, {priority, low}],
    {TimerPid, _Ref} = proc_lib:spawn_opt(?MODULE, init_timer, TimerArgs, TimerOpts),
    {ok, Socket} = ranch:handshake(Ref),
    loop(Socket, TimerPid, TS, IngressTimeoutMs).

-spec loop(dynamic(), pid(), integer(), integer()) -> dynamic().
loop(Socket, TimerPid, TS, IngressTimeoutMs) ->
    inet:setopts(Socket, [{active, once}]),
    receive
        {tcp, Socket, <<Len:16, Bin/binary>>} ->
            loop(Socket, TimerPid, TS, IngressTimeoutMs, Len, Bin);
        {tcp_error, Socket, Reason} ->
            ?LOG_INFO(#{what => tcp_error, reason => Reason}, #{domain => [erldns, listeners]});
        {tcp_closed, Socket} ->
            ok
    after IngressTimeoutMs ->
        gen_tcp:close(Socket)
    end.

-spec loop(inet:socket(), pid(), integer(), integer(), non_neg_integer(), binary()) -> dynamic().
loop(Socket, TimerPid, TS, IngressTimeoutMs, Len, Acc) when Len =:= byte_size(Acc) ->
    handle_if_within_time(Socket, TimerPid, TS, IngressTimeoutMs, Acc);
loop(Socket, TimerPid, TS, IngressTimeoutMs, Len, Acc) ->
    inet:setopts(Socket, [{active, once}]),
    receive
        {tcp, Socket, Bin} ->
            loop(Socket, TimerPid, TS, IngressTimeoutMs, Len, <<Acc/binary, Bin/binary>>);
        {tcp_error, Socket, Reason} ->
            ?LOG_INFO(#{what => tcp_error, reason => Reason}, #{domain => [erldns, listeners]});
        {tcp_closed, Socket} ->
            ok
    after IngressTimeoutMs ->
        gen_tcp:close(Socket)
    end.

handle_if_within_time(Socket, TimerPid, TS, IngressTimeoutMs, Bin) ->
    IngressTimeoutNative = erlang:convert_time_unit(IngressTimeoutMs, millisecond, native),
    case IngressTimeoutNative =< erlang:monotonic_time() - TS of
        false ->
            handle(Socket, TimerPid, TS, Bin);
        true ->
            ?LOG_WARNING(
                #{what => request_timeout, transport => tcp},
                #{domain => [erldns, listeners]}
            ),
            telemetry:execute([erldns, request, dropped], #{count => 1}, #{transport => tcp})
    end.

-spec handle(inet:socket(), pid(), integer(), binary()) -> dynamic().
handle(Socket, TimerPid, TS, Bin) ->
    Measurements = #{monotonic_time => TS, request_size => byte_size(Bin)},
    InitMetadata = #{transport => tcp},
    telemetry:execute([erldns, request, start], Measurements, InitMetadata),
    try
        {ok, {IpAddr, _Port}} = inet:peername(Socket),
        case dns:decode_message(Bin) of
            {trailing_garbage, #dns_message{} = DecodedMessage, TrailingGarbage} ->
                ?LOG_INFO(
                    #{what => trailing_garbage, trailing_garbage => TrailingGarbage},
                    #{domain => [erldns, listeners]}
                ),
                handle_decoded(Socket, TimerPid, TS, DecodedMessage, IpAddr);
            {Error, Message, _} ->
                ErrorMetadata = #{transport => tcp, reason => Error, message => Message},
                request_error_event(ErrorMetadata);
            DecodedMessage ->
                handle_decoded(Socket, TimerPid, TS, DecodedMessage, IpAddr)
        end
    catch
        Class:Reason:Stacktrace ->
            ExceptionMetadata = #{
                transport => tcp, kind => Class, reason => Reason, stacktrace => Stacktrace
            },
            request_error_event(ExceptionMetadata)
    end.

-spec handle_decoded(inet:socket(), pid(), integer(), dns:message(), dynamic()) -> dynamic().
handle_decoded(_, _, _, #dns_message{qr = true}, _) ->
    {error, not_a_question};
handle_decoded(Socket, TimerPid, TS0, DecodedMessage, IpAddr) ->
    forward_dp_to_timer(DecodedMessage, TimerPid),
    InitOpts = #{monotonic_time => TS0, transport => tcp, socket => Socket, host => IpAddr},
    Response = erldns_pipeline:call(DecodedMessage, InitOpts),
    EncodedResponse = erldns_encoder:encode_message(Response),
    exit(TimerPid, kill),
    ok = gen_tcp:send(Socket, [<<(byte_size(EncodedResponse)):16>>, EncodedResponse]),
    measure_time(Response, EncodedResponse, TS0),
    gen_tcp:close(Socket).

request_error_event(Metadata) ->
    telemetry:execute([erldns, request, error], #{count => 1}, Metadata).

measure_time(Response, EncodedResponse, TS0) ->
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

-spec init_timer(integer(), pid()) -> term().
init_timer(IngressTimeoutMs, Parent) ->
    Ref = erlang:monitor(process, Parent),
    receive
        {'DOWN', Ref, process, Parent, _} ->
            ok
    after IngressTimeoutMs ->
        exit(Parent, kill),
        Params = maybe_receive_params(),
        ?LOG_WARNING(
            Params#{what => request_timeout, transport => tcp, worker => Parent},
            #{domain => [erldns, listeners]}
        ),
        telemetry:execute([erldns, request, timeout], #{count => 1}, #{transport => tcp})
    end.

maybe_receive_params() ->
    receive
        P when is_map(P) ->
            P
    after 0 ->
        #{}
    end.

forward_dp_to_timer(Msg, TimerPid) ->
    TimerPid ! #{query => get_query(Msg), dnssec => get_dnssec(Msg)}.

get_query(#dns_message{questions = [#dns_query{name = QName, type = QType} | Rest]}) ->
    #{name => QName, type => QType, extra_queries => ([] =:= Rest)};
get_query(#dns_message{questions = []}) ->
    none.

get_dnssec(#dns_message{additional = [#dns_optrr{dnssec = true} | _]}) ->
    true;
get_dnssec(#dns_message{additional = _}) ->
    false.
