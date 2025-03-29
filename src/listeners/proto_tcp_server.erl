-module(proto_tcp_server).

-include_lib("kernel/include/logger.hrl").
-include_lib("dns_erlang/include/dns.hrl").

-behaviour(ranch_protocol).
-export([start_link/3]).
-export([init/1]).

start_link(Ref, _Transport, _Opts) ->
    SpawnTimeout = 5000,
    %% Allocate a process with just enough memory from init to do the decoding. If this number
    %% is well nailed, the process will finish the whole work and its entire memory deallocated
    %% at once when the process dies, therefore never needing a Garbage Collection.
    SpawnOpts = [{min_heap_size, 1024}],
    %% As the process is very short-lived, `proc_lib` is a much much lighter abstraction
    %% than gen_servers
    proc_lib:start_link(?MODULE, init, [Ref], SpawnTimeout, SpawnOpts).

init(Ref) ->
    %% Notify the supervisor that the children is ready
    proc_lib:init_ack({ok, self()}),
    %% Get the socket from ranch
    {ok, Socket} = ranch:handshake(Ref),
    %% Activate the socket and loop
    inet:setopts(Socket, [{active, once}]),
    loop(Socket).

loop(Socket) ->
    receive
        %% Get the tcp right tcp packet
        {tcp, Socket, <<_Len:16, Bin/binary>>} ->
            handle_tcp_query(Socket, Bin),
            gen_tcp:close(Socket);
        {tcp, Socket, _} ->
            ?LOG_WARNING(#{what => bad_tcp_packet}),
            gen_tcp:close(Socket);
        _Msg ->
            ok
    end.

%% Exact same logic currently shared between `erldns_worker` and `erldns_worker_process`
handle_tcp_query(Socket, Bin) ->
    try
        {ok, {Address, _Port}} = inet:peername(Socket),
        case erldns_decoder:decode_message(Bin) of
            {trailing_garbage, DecodedMessage, TrailingGarbage} ->
                ?LOG_INFO(#{what => trailing_garbage, trailing_garbage => TrailingGarbage}),
                handle_decoded_tcp_message(Socket, DecodedMessage, Address);
            {Error, Message, _} ->
                ?LOG_INFO(#{what => error_decoding, error => Error, message => Message}),
                ok;
            DecodedMessage ->
                handle_decoded_tcp_message(Socket, DecodedMessage, Address)
        end
    catch
        Class:Reason:Stacktrace ->
            ?LOG_ERROR(#{what => error, class => Class, reason => Reason, stacktrace => Stacktrace})
    end.

handle_decoded_tcp_message(Socket, DecodedMessage, Address) ->
    case DecodedMessage#dns_message.qr of
        false ->
            Response = erldns_handler:do_handle(DecodedMessage, Address),
            EncodedMessage = erldns_encoder:encode_message(Response),
            send_tcp_message(Socket, EncodedMessage);
        true ->
            {error, not_a_question}
    end.

send_tcp_message(Socket, EncodedMessage) ->
    BinLength = byte_size(EncodedMessage),
    TcpEncodedMessage = <<BinLength:16, EncodedMessage/binary>>,
    gen_tcp:send(Socket, TcpEncodedMessage).
