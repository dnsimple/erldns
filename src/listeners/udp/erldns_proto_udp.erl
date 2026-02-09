-module(erldns_proto_udp).
-moduledoc false.

-include_lib("kernel/include/logger.hrl").
-include_lib("dns_erlang/include/dns.hrl").

-compile({inline, [handle_udp_work/5, handle_decoded/5]}).
% How many drops before checking system messages.
-define(DRAIN_BUDGET, 500).
-define(LOG_METADATA, #{domain => [erldns, listeners, udp]}).

-behaviour(gen_server).

-export([overrun_handler/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-type timestamp() :: integer().
-type task() ::
    {udp_work, gen_udp:socket(), inet:ip_address(), inet:port_number(), timestamp(), binary()}.
-export_type([task/0]).

-spec overrun_handler([{atom(), term()}, ...]) -> term().
overrun_handler(Args) ->
    ?LOG_WARNING(maps:from_list([{what, request_timeout}, {transport, udp} | Args]), ?LOG_METADATA),
    telemetry:execute([erldns, request, timeout], #{count => 1}, #{transport => udp}).

-spec init(non_neg_integer()) -> {ok, erldns_codel:codel()}.
init(IngressTimeoutMs) ->
    {ok, erldns_codel:new(IngressTimeoutMs)}.

-spec handle_call(term(), gen_server:from(), erldns_codel:codel()) ->
    {reply, not_implemented, erldns_codel:codel()}.
handle_call(Call, From, Codel) ->
    ?LOG_INFO(#{what => unexpected_call, from => From, call => Call}, ?LOG_METADATA),
    {reply, not_implemented, Codel}.

-spec handle_cast(task() | erldns_async_pool:done(), erldns_codel:codel()) ->
    {noreply, erldns_codel:codel()}.
handle_cast({udp_work, Socket, IpAddr, Port, IngressTs, Bin}, Codel) ->
    process_udp_work(Codel, Socket, IpAddr, Port, IngressTs, Bin, false);
handle_cast({async_done, Continuation}, Codel) ->
    process_async_continuation(Codel, Continuation, false);
handle_cast(Cast, Codel) ->
    ?LOG_INFO(#{what => unexpected_cast, cast => Cast}, ?LOG_METADATA),
    {noreply, Codel}.

-spec handle_info(term(), erldns_codel:codel()) -> {noreply, erldns_codel:codel()}.
handle_info(Info, Codel) ->
    ?LOG_INFO(#{what => unexpected_info, info => Info}, ?LOG_METADATA),
    {noreply, Codel}.

-spec process_udp_work(Codel, Socket, IpAddr, Port, IngressTs, Bin, Budget) -> Result when
    Result :: {noreply, Codel},
    Codel :: erldns_codel:codel(),
    Socket :: inet:socket(),
    IpAddr :: inet:ip_address(),
    Port :: inet:port_number(),
    IngressTs :: timestamp(),
    Bin :: dns:message_bin(),
    Budget :: false | non_neg_integer().
process_udp_work(Codel, Socket, IpAddr, Port, IngressTs, Bin, Budget) ->
    Now = erlang:monotonic_time(),
    {message_queue_len, QueueLen} = process_info(self(), message_queue_len),
    case erldns_codel:dequeue(Codel, Now, IngressTs, QueueLen) of
        {continue, Codel1} ->
            handle_udp_work(Socket, IpAddr, Port, IngressTs, Bin),
            drop_loop(Codel1, Budget);
        {drop, Codel1} ->
            ?LOG_WARNING(#{what => request_dropped, transport => udp}, ?LOG_METADATA),
            telemetry:execute([erldns, request, dropped], #{count => 1}, #{transport => udp}),
            drop_loop(Codel1, budget(Budget))
    end.

-spec process_async_continuation(Codel, Continuation, Budget) -> Result when
    Result :: {noreply, Codel},
    Codel :: erldns_codel:codel(),
    Continuation :: erldns_pipeline:continuation(),
    Budget :: false | non_neg_integer().
process_async_continuation(Codel, Continuation, Budget) ->
    #{inet_socket := Socket, host := IpAddr, port := Port, monotonic_time := IngressTs} =
        erldns_pipeline:get_continuation_opts(Continuation),
    Now = erlang:monotonic_time(),
    {message_queue_len, QueueLen} = process_info(self(), message_queue_len),
    case erldns_codel:dequeue(Codel, Now, IngressTs, QueueLen) of
        {continue, Codel1} ->
            handle_async_reply(Socket, IpAddr, Port, IngressTs, Continuation),
            drop_loop(Codel1, Budget);
        {drop, Codel1} ->
            ?LOG_WARNING(#{what => request_dropped, transport => udp}, ?LOG_METADATA),
            telemetry:execute([erldns, request, dropped], #{count => 1}, #{transport => udp}),
            drop_loop(Codel1, budget(Budget))
    end.

%% If it is the first time we need to use a budget, it will start with the max
budget(false) -> ?DRAIN_BUDGET;
budget(N) -> N.

%% The Recursive Loop (RFC "while" Loop equivalent)
%% Budget exhausted, we must yield to let the gen_server handle system messages.
drop_loop(Codel, 0) ->
    {noreply, Codel};
drop_loop(Codel, false) ->
    {noreply, Codel};
drop_loop(Codel, Budget) ->
    receive
        {'$gen_cast', {udp_work, Socket, IpAddr, Port, IngressTs, Bin}} ->
            process_udp_work(Codel, Socket, IpAddr, Port, IngressTs, Bin, Budget - 1);
        {'$gen_cast', {async_done, Continuation}} ->
            process_async_continuation(Codel, Continuation, Budget - 1)
    after 0 ->
        {noreply, Codel}
    end.

-spec handle_async_reply(Socket, IpAddr, Port, IngressTs, Continuation) -> ok when
    Socket :: inet:socket(),
    IpAddr :: inet:ip_address(),
    Port :: inet:port_number(),
    IngressTs :: timestamp(),
    Continuation :: erldns_pipeline:continuation().
handle_async_reply(Socket, IpAddr, Port, IngressTs, Continuation) ->
    Response = erldns_pipeline:resume_pipeline(Continuation),
    handle_pipeline_response(Socket, IpAddr, Port, IngressTs, Response).

-spec handle_udp_work(Socket, IpAddr, Port, IngressTs, Bin) -> ok when
    Socket :: inet:socket(),
    IpAddr :: inet:ip_address(),
    Port :: inet:port_number(),
    IngressTs :: timestamp(),
    Bin :: dns:message_bin().
handle_udp_work(Socket, IpAddr, Port, TS, Bin) ->
    try
        Measurements = #{monotonic_time => TS, request_size => byte_size(Bin)},
        InitMetadata = #{transport => udp},
        telemetry:execute([erldns, request, start], Measurements, InitMetadata),
        Decoded = dns:decode_query(Bin),
        handle_decoded(Socket, IpAddr, Port, TS, Decoded)
    catch
        Class:Reason:Stacktrace ->
            ExceptionMetadata = #{
                transport => udp, kind => Class, reason => Reason, stacktrace => Stacktrace
            },
            request_error_event(ExceptionMetadata)
    end.

-spec handle_decoded(Socket, IpAddr, Port, TS0, Msg) -> ok when
    Socket :: inet:socket(),
    IpAddr :: inet:ip_address(),
    Port :: inet:port_number(),
    TS0 :: timestamp(),
    Msg :: {dns:decode_error(), dns:message() | undefined, binary()} | dns:message().
handle_decoded(Socket, IpAddr, Port, TS0, #dns_message{} = Msg) ->
    InitOpts = #{
        monotonic_time => TS0,
        transport => udp,
        socket => {Socket, Port},
        inet_socket => Socket,
        host => IpAddr,
        port => Port
    },
    Response = erldns_pipeline:call(Msg, InitOpts),
    handle_pipeline_response(Socket, IpAddr, Port, TS0, Response);
handle_decoded(Socket, IpAddr, Port, TS0, {trailing_garbage, #dns_message{} = Msg, Trailing}) ->
    Metadata = #{
        transport => udp,
        reason => trailing_garbage,
        trailing_garbage => Trailing,
        message => Msg,
        monotonic_time => TS0
    },
    request_error_event(Metadata),
    handle_decoded(Socket, IpAddr, Port, TS0, Msg);
handle_decoded(Socket, IpAddr, Port, TS0, {notimp, #dns_message{} = Msg, _}) ->
    Metadata = #{transport => udp, reason => notimp, message => Msg, monotonic_time => TS0},
    request_error_event(Metadata),
    handle_pipeline_response(Socket, IpAddr, Port, TS0, Msg);
handle_decoded(_, _, _, TS0, {Error, Msg, _}) ->
    Metadata = #{transport => udp, reason => Error, message => Msg, monotonic_time => TS0},
    request_error_event(Metadata).

-spec handle_pipeline_response(Socket, IpAddr, Port, TS, PipeResult) -> ok when
    PipeResult :: erldns_pipeline:result(),
    IpAddr :: inet:ip_address(),
    Port :: inet:port_number(),
    TS :: timestamp(),
    Socket :: gen_udp:socket().
handle_pipeline_response(_, _, _, _, halt) ->
    ok;
handle_pipeline_response(_, _, _, _, {suspend, Continuation}) ->
    erldns_async_pool:cast(Continuation);
handle_pipeline_response(Socket, IpAddr, Port, TS0, #dns_message{} = Response) ->
    Result = erldns_encoder:encode_message(Response, #{}),
    EncodedResponse =
        case Result of
            {truncated, Enc, _TsigMac, #dns_message{} = _Message} -> Enc;
            {truncated, Enc, #dns_message{} = _Message} -> Enc;
            {Enc, _TsigMac} -> Enc;
            Enc -> Enc
        end,
    gen_udp:send(Socket, IpAddr, Port, EncodedResponse),
    measure_time(Response, EncodedResponse, TS0).

request_error_event(Metadata) ->
    telemetry:execute([erldns, request, error], #{count => 1}, Metadata).

measure_time(Response, EncodedResponse, TS0) ->
    ?LOG_DEBUG(#{what => udp_request_finished, dns_message => Response}, ?LOG_METADATA),
    TS1 = erlang:monotonic_time(),
    Measurements = #{
        monotonic_time => TS1,
        duration => TS1 - TS0,
        response_size => byte_size(EncodedResponse)
    },
    DnsSec = proplists:get_bool(dnssec, erldns_edns:get_opts(Response)),
    Metadata = #{
        transport => udp,
        dnssec => DnsSec,
        dns_message => Response
    },
    telemetry:execute([erldns, request, stop], Measurements, Metadata).
