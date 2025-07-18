-module(erldns_proto_udp).
-moduledoc false.

-include_lib("kernel/include/logger.hrl").
-include_lib("dns_erlang/include/dns.hrl").

-compile({inline, [handle_if_within_time/6, handle/5]}).

-behaviour(gen_server).

-define(MIN_PACKET_SIZE, 512).
-define(MAX_PACKET_SIZE, 1232).

-export([overrun_handler/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-type task() :: {gen_udp:socket(), inet:ip_address(), inet:port_number(), integer(), binary()}.
-opaque state() :: non_neg_integer().
-export_type([task/0, state/0]).

-spec overrun_handler([{atom(), term()}, ...]) -> term().
overrun_handler(Args) ->
    ?LOG_WARNING(
        maps:from_list([{what, request_timeout}, {transport, udp} | Args]),
        #{domain => [erldns, listeners]}
    ),
    telemetry:execute([erldns, request, timeout], #{count => 1}, #{transport => udp}).

-spec init(non_neg_integer()) -> {ok, state()}.
init(IngressTimeoutNative) ->
    {ok, IngressTimeoutNative}.

-spec handle_call(term(), gen_server:from(), state()) -> {reply, not_implemented, state()}.
handle_call(Call, From, State) ->
    ?LOG_INFO(
        #{what => unexpected_call, from => From, call => Call},
        #{domain => [erldns, listeners]}
    ),
    {reply, not_implemented, State}.

-spec handle_cast(task(), state()) -> {noreply, state()}.
handle_cast({Socket, IpAddr, Port, TS, Bin}, IngressTimeoutNative) ->
    handle_if_within_time(Socket, IpAddr, Port, TS, Bin, IngressTimeoutNative),
    {noreply, IngressTimeoutNative};
handle_cast(Cast, State) ->
    ?LOG_INFO(#{what => unexpected_cast, cast => Cast}, #{domain => [erldns, listeners]}),
    {noreply, State}.

-spec handle_info(term(), state()) -> {noreply, state()}.
handle_info(Info, State) ->
    ?LOG_INFO(#{what => unexpected_info, info => Info}, #{domain => [erldns, listeners]}),
    {noreply, State}.

handle_if_within_time(Socket, IpAddr, Port, TS, Bin, IngressTimeoutNative) ->
    case IngressTimeoutNative =< erlang:monotonic_time() - TS of
        false ->
            handle(Socket, IpAddr, Port, TS, Bin);
        true ->
            ?LOG_WARNING(
                #{what => request_timeout, transport => udp},
                #{domain => [erldns, listeners]}
            ),
            telemetry:execute([erldns, request, dropped], #{count => 1}, #{transport => udp})
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
                    #{domain => [erldns, listeners]}
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
handle_decoded(Socket, IpAddr, Port, DecodedMessage0, TS0) ->
    DecodedMessage = normalize_edns_max_payload_size(DecodedMessage0),
    InitOpts = #{monotonic_time => TS0, transport => udp, host => IpAddr},
    Response = erldns_pipeline:call(DecodedMessage, InitOpts),
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

request_error_event(Metadata) ->
    telemetry:execute([erldns, request, error], #{count => 1}, Metadata).

measure_time(Response, EncodedResponse, TS0) ->
    ?LOG_DEBUG(
        #{what => udp_request_finished, dns_message => Response},
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
        transport => udp,
        dnssec => DnsSec,
        dns_message => Response
    },
    telemetry:execute([erldns, request, stop], Measurements, Metadata).
