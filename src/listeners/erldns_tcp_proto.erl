-module(erldns_tcp_proto).
-moduledoc false.

-include_lib("kernel/include/logger.hrl").
-include_lib("dns_erlang/include/dns.hrl").

-behaviour(ranch_protocol).
-export([start_link/3]).
-export([init/1]).
-export([init_timer/2]).

-spec start_link(ranch:ref(), module(), any()) -> dynamic().
start_link(Ref, _Transport, _Opts) ->
    SpawnOpts = [{min_heap_size, 500}],
    proc_lib:start_link(?MODULE, init, [Ref], 5000, SpawnOpts).

-spec init(ranch:ref()) -> dynamic().
init(Ref) ->
    Self = self(),
    proc_lib:init_ack({ok, Self}),
    proc_lib:set_label(?MODULE),
    TS = erlang:monotonic_time(),
    Timeout = erldns_config:ingress_tcp_request_timeout(),
    {Pid, _Ref} = proc_lib:spawn_opt(?MODULE, init_timer, [Timeout, Self], [monitor]),
    {ok, Socket} = ranch:handshake(Ref),
    loop(Socket, TS, Timeout, Pid).

-spec init_timer(integer(), pid()) -> any().
init_timer(Timeout, Parent) ->
    receive
    after Timeout -> exit(Parent, kill)
    end.

loop(Socket, TS, Timeout, Pid) ->
    inet:setopts(Socket, [{active, once}]),
    receive
        {tcp, Socket, <<Len:16, Bin/binary>>} ->
            loop(Socket, TS, Timeout, Pid, Len, Bin);
        {tcp_error, Socket, Reason} ->
            ?LOG_INFO(#{what => tcp_error, reason => Reason});
        {tcp_closed, Socket} ->
            ok
    after Timeout ->
        gen_tcp:close(Socket)
    end.

loop(Socket, TS, _, Pid, Len, Acc) when Len =:= byte_size(Acc) ->
    handle_tcp_query(Socket, TS, Pid, Acc);
loop(Socket, TS, Timeout, Pid, Len, Acc) ->
    inet:setopts(Socket, [{active, once}]),
    receive
        {tcp, Socket, Bin} ->
            loop(Socket, TS, Timeout, Pid, Len, <<Acc/binary, Bin/binary>>);
        {tcp_error, Socket, Reason} ->
            ?LOG_INFO(#{what => tcp_error, reason => Reason});
        {tcp_closed, Socket} ->
            ok
    after Timeout ->
        gen_tcp:close(Socket)
    end.

handle_tcp_query(Socket, TS, Pid, Bin) ->
    try
        {ok, {Address, _Port}} = inet:peername(Socket),
        case erldns_decoder:decode_message(Bin) of
            {trailing_garbage, DecodedMessage, TrailingGarbage} ->
                ?LOG_INFO(#{what => trailing_garbage, trailing_garbage => TrailingGarbage}),
                handle_decoded_tcp_message(Socket, TS, Pid, DecodedMessage, Address);
            {Error, Message, _} ->
                ?LOG_INFO(#{what => error_decoding, error => Error, message => Message}),
                ok;
            DecodedMessage ->
                handle_decoded_tcp_message(Socket, TS, Pid, DecodedMessage, Address)
        end
    catch
        Class:Reason:Stacktrace ->
            ?LOG_ERROR(#{
                what => handle_tcp_query_error,
                class => Class,
                reason => Reason,
                stacktrace => Stacktrace
            })
    end.

handle_decoded_tcp_message(Socket, TS0, Pid, DecodedMessage, Address) ->
    case DecodedMessage#dns_message.qr of
        false ->
            Response = erldns_handler:do_handle(DecodedMessage, Address),
            EncodedResponse = erldns_encoder:encode_message(Response),
            exit(Pid, kill),
            ok = gen_tcp:send(Socket, [<<(byte_size(EncodedResponse)):16>>, EncodedResponse]),
            measure_time(DecodedMessage, EncodedResponse, tcp, TS0);
        true ->
            {error, not_a_question}
    end.

measure_time(DecodedMessage, EncodedResponse, Protocol, TS0) ->
    TS1 = erlang:monotonic_time(),
    Measurements = #{
        monotonic_time => TS1,
        duration => TS1 - TS0,
        response_size => byte_size(EncodedResponse)
    },
    DnsSec = proplists:get_bool(dnssec, erldns_edns:get_opts(DecodedMessage)),
    Metadata = #{
        protocol => Protocol,
        dnssec => DnsSec
    },
    telemetry:execute([erldns, request, processed], Measurements, Metadata).
