-module(erldns_proto_udp).
-moduledoc false.

-include_lib("kernel/include/logger.hrl").
-include_lib("dns_erlang/include/dns.hrl").

-compile({inline, [handle/5]}).

-behaviour(gen_server).

-define(MIN_PACKET_SIZE, 512).
-define(MAX_PACKET_SIZE, 1232).

-export([overrun_handler/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-type task() :: {gen_udp:socket(), inet:ip_address(), inet:port_number(), integer(), binary()}.
-type state() :: nostate.

-spec overrun_handler([{atom(), term()}, ...]) -> any().
overrun_handler(Args) ->
    ?LOG_WARNING(
        maps:from_list([{what, request_timeout}, {transport, udp} | Args]),
        #{domain => [erldns, listeners]}
    ),
    telemetry:execute([erldns, request, timeout], #{count => 1}, #{transport => udp}).

-spec init(noargs) -> {ok, state()}.
init(noargs) ->
    {ok, nostate}.

-spec handle_call(term(), gen_server:from(), state()) -> {reply, not_implemented, state()}.
handle_call(Call, From, State) ->
    ?LOG_INFO(
        #{what => unexpected_call, from => From, call => Call},
        #{domain => [erldns, listeners]}
    ),
    {reply, not_implemented, State}.

-spec handle_cast(task(), state()) -> {noreply, state()}.
handle_cast({Socket, IpAddr, Port, TS, Bin}, State) ->
    handle(Socket, IpAddr, Port, TS, Bin),
    {noreply, State};
handle_cast(Cast, State) ->
    ?LOG_INFO(#{what => unexpected_cast, cast => Cast}, #{domain => [erldns, listeners]}),
    {noreply, State}.

-spec handle_info(term(), state()) -> {noreply, state()}.
handle_info(Info, State) ->
    ?LOG_INFO(#{what => unexpected_info, info => Info}, #{domain => [erldns, listeners]}),
    {noreply, State}.

-spec handle(inet:socket(), inet:ip_address(), inet:port_number(), integer(), binary()) ->
    dynamic().
handle(Socket, IpAddr, Port, TS, Bin) ->
    Measurements = #{monotonic_time => TS, request_size => byte_size(Bin)},
    Metadata = #{transport => udp},
    telemetry:execute([erldns, request, start], Measurements, Metadata),
    try
        case dns:decode_message(Bin) of
            {trailing_garbage, DecodedMessage, TrailingGarbage} ->
                ?LOG_INFO(
                    #{what => trailing_garbage, trailing_garbage => TrailingGarbage},
                    #{domain => [erldns, listeners]}
                ),
                handle_decoded(Socket, IpAddr, Port, DecodedMessage, TS);
            {Error, Message, _} ->
                ErrorMetadata = #{transport => udp, reason => Error, message => Message},
                telemetry:execute([erldns, request, error], #{count => 1}, ErrorMetadata);
            DecodedMessage ->
                handle_decoded(Socket, IpAddr, Port, DecodedMessage, TS)
        end
    catch
        Class:Reason:Stacktrace ->
            MetaData = #{
                transport => udp, kind => Class, reason => Reason, stacktrace => Stacktrace
            },
            telemetry:execute([erldns, request, error], #{count => 1}, MetaData)
    end.

-spec handle_decoded(
    inet:socket(), inet:ip_address(), inet:port_number(), dns:message(), dynamic()
) -> dynamic().
handle_decoded(_, _, _, #dns_message{qr = true}, _) ->
    {error, not_a_question};
handle_decoded(Socket, IpAddr, Port, DecodedMessage0, TS0) ->
    DecodedMessage = normalize_edns_max_payload_size(DecodedMessage0),
    Response = erldns_pipeline:call(DecodedMessage, #{transport => udp, host => IpAddr}),
    Result = erldns_encoder:encode_message(Response, #{}),
    EncodedResponse =
        case Result of
            {false, Enc} -> Enc;
            {false, Enc, _TsigMac} -> Enc;
            {true, Enc, #dns_message{} = _Message} -> Enc;
            {true, Enc, _TsigMac, #dns_message{} = _Message} -> Enc
        end,
    gen_udp:send(Socket, IpAddr, Port, EncodedResponse),
    ?LOG_DEBUG(
        #{what => tcp_request, request => DecodedMessage, response => Response},
        #{domain => [erldns, listeners]}
    ),
    measure_time(DecodedMessage, EncodedResponse, TS0).

-spec normalize_edns_max_payload_size(dns:message()) -> dns:message().
normalize_edns_max_payload_size(Message) ->
    case Message#dns_message.additional of
        [#dns_optrr{udp_payload_size = Size} = OptRR | RestAdditional] ->
            case ?MIN_PACKET_SIZE =< Size andalso Size =< ?MAX_PACKET_SIZE of
                true ->
                    Message;
                false ->
                    OptRR1 = OptRR#dns_optrr{udp_payload_size = ?MAX_PACKET_SIZE},
                    Message#dns_message{additional = [OptRR1 | RestAdditional]}
            end;
        _ ->
            Message
    end.

measure_time(DecodedMessage, EncodedResponse, TS0) ->
    TS1 = erlang:monotonic_time(),
    Measurements = #{
        monotonic_time => TS1,
        duration => TS1 - TS0,
        response_size => byte_size(EncodedResponse)
    },
    DnsSec = proplists:get_bool(dnssec, erldns_edns:get_opts(DecodedMessage)),
    Metadata = #{
        transport => udp,
        dnssec => DnsSec
    },
    telemetry:execute([erldns, request, stop], Measurements, Metadata).
