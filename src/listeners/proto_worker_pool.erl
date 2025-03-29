-module(proto_worker_pool).

-include_lib("kernel/include/logger.hrl").
-include_lib("dns_erlang/include/dns.hrl").

-compile({inline, [take_next/2, return/2, handle_udp_query/6]}).

-behaviour(gen_server).

%% Public API
-export([new/1, give_to_worker/3]).

-export([start_link/1]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

%%%===================================================================
%%% API
%%%===================================================================

start_link(State) ->
    gen_server:start_link(?MODULE, State, []).

give_to_worker(Ref, Workers, Payload) ->
    Pid = take_next(Ref, Workers),
    Pid ! Payload.

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init(State) ->
    case ets:lookup_element(erldns_listener, workers, 2, undefined) of
        undefined ->
            ets:insert(erldns_listener, {workers, {self()}});
        WorkerTuple when is_tuple(WorkerTuple) ->
            List = tuple_to_list(WorkerTuple),
            NewWorkerTuple = list_to_tuple([self() | List]),
            ets:insert(erldns_listener, {workers, NewWorkerTuple})
    end,
    {ok, State}.

handle_call(_Request, _From, State) ->
    {reply, ok, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({Socket, Ip, Port, Bin, TS}, {Ref, Id, Skerl} = State) ->
    handle_udp_query(Socket, Ip, Port, Bin, TS, Skerl),
    return(Ref, Id),
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

% [
%     Size, NextTake, NextReturn,
%     WorkerId1, WorkerId2, ...
% ]

-define(NEXT_POS, 1).
-define(SIZE_POS, 2).
-define(TAKE_POS, 3).
-define(RETURN_POS, 4).
-define(HEADER_SIZE, 4).

-spec new(pos_integer()) -> atomics:atomics_ref().
new(Size) ->
    Ref = atomics:new(Size + ?HEADER_SIZE, []),
    atomics:put(Ref, ?SIZE_POS, Size),
    atomics:put(Ref, ?NEXT_POS, 1),
    [atomics:put(Ref, Id + ?HEADER_SIZE, Id) || Id <- lists:seq(1, Size)],
    Ref.

take_next(Ref, Workers) ->
    Size = tuple_size(Workers),
    Current = atomics:get(Ref, ?NEXT_POS),
    Next = Current rem Size + 1,
    _ = atomics:compare_exchange(Ref, ?NEXT_POS, Current, Next),
    element(Next, Workers).
    % NextTake = atomics:get(Ref, ?TAKE_POS),
    % case atomics:exchange(Ref, NextTake + ?HEADER_SIZE + 1, 0) of
    %     0 ->
    %         empty;
    %     Id ->
    %         case NextTake + 1 < atomics:get(Ref, ?SIZE_POS) of
    %             true ->
    %                 atomics:put(Ref, ?TAKE_POS, NextTake + 1);
    %             _ ->
    %                 atomics:put(Ref, ?TAKE_POS, 0)
    %         end,
    %         Id
    % end.

-spec return(atomics:atomics_ref(), pos_integer()) -> NeedNotify :: boolean().
return(Ref, Id) ->
    Size = atomics:get(Ref, ?SIZE_POS),
    NextReturn = atomics:add_get(Ref, ?RETURN_POS, 1),
    NextReturn =:= Size andalso atomics:sub(Ref, ?RETURN_POS, Size),
    ReturnPos = ((NextReturn - 1) rem Size),
    atomics:put(Ref, ReturnPos + ?HEADER_SIZE + 1, Id),
    atomics:get(Ref, ?TAKE_POS) =:= ReturnPos.

handle_udp_query(Socket, Ip, Port, Bin, TS, Skerl) ->
    try
        case erldns_decoder:decode_message(Bin) of
            {trailing_garbage, DecodedMessage, TrailingGarbage} ->
                ?LOG_INFO(#{what => trailing_garbage, trailing_garbage => TrailingGarbage}),
                handle_decoded_udp_message(Socket, Ip, Port, DecodedMessage, TS, Skerl);
            {Error, Message, _} = Dec ->
                ?LOG_INFO(#{what => error_decoding, error => Error, message => Message}),
                erlang:error(Dec);
            DecodedMessage ->
                handle_decoded_udp_message(Socket, Ip, Port, DecodedMessage, TS, Skerl)
        end
    catch
        Class:Reason:Stacktrace ->
            ?LOG_ERROR(#{what => error, class => Class, reason => Reason, stacktrace => Stacktrace}),
            ok
    end.

handle_decoded_udp_message(Socket, Ip, Port, DecodedMessage, TS, _Skerl) ->
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
            % ddskerl_counters:insert(Skerl, erlang:monotonic_time() - TS);
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
