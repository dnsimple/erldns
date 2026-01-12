-module(erldns_proto_udp).
-moduledoc false.

-include_lib("kernel/include/logger.hrl").
-include_lib("dns_erlang/include/dns.hrl").

-compile({inline, [process_packet/7, handle/5]}).
% How many drops before checking system messages.
-define(DRAIN_BUDGET, 500).
-define(LOG_METADATA, #{domain => [erldns, listeners, udp]}).

-behaviour(gen_server).

-export([overrun_handler/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-type task() ::
    {udp_work, gen_udp:socket(), inet:ip_address(), inet:port_number(), integer(), binary()}.
-opaque codel() :: erldns_codel:codel().
-export_type([task/0, codel/0]).

-spec overrun_handler([{atom(), term()}, ...]) -> term().
overrun_handler(Args) ->
    ?LOG_WARNING(maps:from_list([{what, request_timeout}, {transport, udp} | Args]), ?LOG_METADATA),
    telemetry:execute([erldns, request, timeout], #{count => 1}, #{transport => udp}).

-spec init(non_neg_integer()) -> {ok, codel()}.
init(IngressTimeoutMs) ->
    {ok, erldns_codel:new(IngressTimeoutMs)}.

-spec handle_call(term(), gen_server:from(), codel()) -> {reply, not_implemented, codel()}.
handle_call(Call, From, Codel) ->
    ?LOG_INFO(#{what => unexpected_call, from => From, call => Call}, ?LOG_METADATA),
    {reply, not_implemented, Codel}.

-spec handle_cast(task(), codel()) -> {noreply, codel()}.
handle_cast({udp_work, Socket, IpAddr, Port, IngressTs, Bin}, Codel) ->
    process_packet(Codel, ?DRAIN_BUDGET, Socket, IpAddr, Port, IngressTs, Bin);
handle_cast(Cast, Codel) ->
    ?LOG_INFO(#{what => unexpected_cast, cast => Cast}, ?LOG_METADATA),
    {noreply, Codel}.

-spec handle_info(term(), codel()) -> {noreply, codel()}.
handle_info(Info, Codel) ->
    ?LOG_INFO(#{what => unexpected_info, info => Info}, ?LOG_METADATA),
    {noreply, Codel}.

-spec process_packet(Codel, Budget, Socket, IpAddr, Port, IngressTs, Bin) -> {noreply, Codel} when
    Socket :: inet:socket(),
    IpAddr :: inet:ip_address(),
    Port :: inet:port_number(),
    IngressTs :: integer(),
    Bin :: dns:message_bin(),
    Budget :: integer(),
    Codel :: codel().
process_packet(Codel, Budget, Socket, IpAddr, Port, IngressTs, Bin) ->
    Now = erlang:monotonic_time(),
    {message_queue_len, QueueLen} = process_info(self(), message_queue_len),
    case erldns_codel:dequeue(Codel, Now, IngressTs, QueueLen) of
        {continue, Codel1} ->
            handle(Socket, IpAddr, Port, IngressTs, Bin),
            {noreply, Codel1};
        {drop, Codel1} ->
            ?LOG_WARNING(#{what => request_dropped, transport => udp}, ?LOG_METADATA),
            telemetry:execute([erldns, request, dropped], #{count => 1}, #{transport => udp}),
            drop_loop(Codel1, Budget)
    end.

%% The Recursive Loop (RFC "while" Loop equivalent)
%% Budget exhausted, we must yield to let the gen_server handle system messages.
drop_loop(Codel, 0) ->
    {noreply, Codel};
drop_loop(Codel, Budget) ->
    receive
        {udp_work, Socket, IpAddr, Port, IngressTs, Bin} ->
            process_packet(Codel, Budget - 1, Socket, IpAddr, Port, IngressTs, Bin)
    after 0 ->
        {noreply, Codel}
    end.

-spec handle(inet:socket(), inet:ip_address(), inet:port_number(), integer(), binary()) ->
    dynamic().
handle(Socket, IpAddr, Port, TS, Bin) ->
    Measurements = #{monotonic_time => TS, request_size => byte_size(Bin)},
    InitMetadata = #{transport => udp},
    telemetry:execute([erldns, request, start], Measurements, InitMetadata),
    try
        case dns:decode_message(Bin) of
            {trailing_garbage, DecodedMessage, TrailingGarbage} ->
                ?LOG_INFO(
                    #{what => trailing_garbage, trailing_garbage => TrailingGarbage},
                    ?LOG_METADATA
                ),
                handle_decoded(Socket, IpAddr, Port, DecodedMessage, TS);
            {Error, Message, _} ->
                ErrorMetadata = #{transport => udp, reason => Error, message => Message},
                request_error_event(ErrorMetadata);
            DecodedMessage ->
                handle_decoded(Socket, IpAddr, Port, DecodedMessage, TS)
        end
    catch
        Class:Reason:Stacktrace ->
            ExceptionMetadata = #{
                transport => udp, kind => Class, reason => Reason, stacktrace => Stacktrace
            },
            request_error_event(ExceptionMetadata)
    end.

-spec handle_decoded(Socket, IpAddr, Port, DecodedMessage, TS0) -> Result when
    Socket :: inet:socket(),
    IpAddr :: inet:ip_address(),
    Port :: inet:port_number(),
    DecodedMessage :: dns:message(),
    TS0 :: integer(),
    Result :: dynamic().
handle_decoded(_, _, _, #dns_message{qr = true}, _) ->
    {error, not_a_question};
handle_decoded(Socket, IpAddr, Port, DecodedMessage, TS0) ->
    InitOpts = #{monotonic_time => TS0, transport => udp, socket => {Socket, Port}, host => IpAddr},
    Response = erldns_pipeline:call(DecodedMessage, InitOpts),
    handle_pipeline_response(Socket, IpAddr, Port, TS0, Response).

handle_pipeline_response(_, _, _, _, halt) ->
    ok;
handle_pipeline_response(Socket, IpAddr, Port, TS0, #dns_message{} = Response) ->
    Result = erldns_encoder:encode_message(Response, #{}),
    EncodedResponse =
        case Result of
            {false, Enc} -> Enc;
            {false, Enc, _TsigMac} -> Enc;
            {true, Enc, #dns_message{} = _Message} -> Enc;
            {true, Enc, _TsigMac, #dns_message{} = _Message} -> Enc
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
