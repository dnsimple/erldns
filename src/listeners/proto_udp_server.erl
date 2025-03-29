-module(proto_udp_server).

-include_lib("kernel/include/logger.hrl").
-include_lib("dns_erlang/include/dns.hrl").

-export([start_link/5]).
-export([init/5]).

start_link(Socket, Ip, Port, Bin, TS) ->
    SpawnTimeout = 5000,
    SpawnOpts = [{min_heap_size, 1024}],
    proc_lib:start_link(?MODULE, init, [Socket, Ip, Port, Bin, TS], SpawnTimeout, SpawnOpts).

init(Socket, Ip, Port, Bin, TS) ->
    proc_lib:set_label({?MODULE, Ip, Port}),
    %% Notify the supervisor that the children is ready
    proc_lib:init_ack({ok, self()}),
    handle_udp_query(Socket, Ip, Port, Bin, TS).

%% Exact same logic currently shared between `erldns_worker` and `erldns_worker_process`
handle_udp_query(Socket, Ip, Port, Bin, TS) ->
    try
        case erldns_decoder:decode_message(Bin) of
            {trailing_garbage, DecodedMessage, TrailingGarbage} ->
                ?LOG_INFO(#{what => trailing_garbage, trailing_garbage => TrailingGarbage}),
                handle_decoded_udp_message(Socket, Ip, Port, DecodedMessage, TS);
            {Error, Message, _} = Dec ->
                ?LOG_INFO(#{what => error_decoding, error => Error, message => Message}),
                erlang:error(Dec);
            DecodedMessage ->
                handle_decoded_udp_message(Socket, Ip, Port, DecodedMessage, TS)
        end
    catch
        Class:Reason:Stacktrace ->
            ?LOG_ERROR(#{what => error, class => Class, reason => Reason, stacktrace => Stacktrace}),
            erlang:raise(Class, Reason, Stacktrace)
    end.

handle_decoded_udp_message(Socket, Ip, Port, DecodedMessage, TS) ->
    case DecodedMessage#dns_message.qr of
        false ->
            Response = erldns_handler:do_handle(DecodedMessage, Ip),
            EncodedMessage = erldns_encoder:encode_message(Response),
            Result = erldns_encoder:encode_message(Response, [{max_size, max_payload_size(Response)}]),
            case Result of
                {false, EncodedMessage} ->
                    gen_udp:send(Socket, Ip, Port, EncodedMessage);
                {true, EncodedMessage, Message} when is_record(Message, dns_message) ->
                    gen_udp:send(Socket, Ip, Port, EncodedMessage);
                {false, EncodedMessage, _TsigMac} ->
                    gen_udp:send(Socket, Ip, Port, EncodedMessage);
                {true, EncodedMessage, _TsigMac, _Message} ->
                    gen_udp:send(Socket, Ip, Port, EncodedMessage)
            end,
            prometheus_quantile_summary:observe(udp_query_microseconds, [], erlang:monotonic_time() - TS);
        true ->
            {error, not_a_question}
    end.

-define(MAX_PACKET_SIZE, 512).
max_payload_size(Message) ->
    case Message#dns_message.additional of
        [Opt | _] when is_record(Opt, dns_optrr) ->
            Size = Opt#dns_optrr.udp_payload_size,
            case Size < ?MAX_PACKET_SIZE of
                true -> Size;
                false -> ?MAX_PACKET_SIZE
            end;
        _ ->
            ?MAX_PACKET_SIZE
    end.
