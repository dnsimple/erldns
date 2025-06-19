-module(erldns_proto_udp_acceptor).
-moduledoc false.

-include_lib("kernel/include/logger.hrl").

-define(ACTIVE, 100).

-behaviour(gen_server).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-record(udp_acceptor, {
    name :: atom(),
    socket :: gen_udp:socket()
}).
-type state() :: #udp_acceptor{}.

-spec init({atom(), [gen_udp:open_option()]}) -> {ok, state()}.
init({Name, SocketOpts}) ->
    process_flag(trap_exit, true),
    proc_lib:set_label(?MODULE),
    Socket = create_socket(SocketOpts),
    {ok, #udp_acceptor{name = Name, socket = Socket}}.

-spec handle_call(term(), gen_server:from(), state()) -> {reply, not_implemented, state()}.
handle_call(Call, From, State) ->
    ?LOG_INFO(
        #{what => unexpected_call, from => From, call => Call},
        #{domain => [erldns, listeners]}
    ),
    {reply, not_implemented, State}.

-spec handle_cast(term(), state()) -> {noreply, state()}.
handle_cast(Cast, State) ->
    ?LOG_INFO(#{what => unexpected_cast, cast => Cast}, #{domain => [erldns, listeners]}),
    {noreply, State}.

-spec handle_info(term(), state()) -> {noreply, state()} | {stop, term(), state()}.
handle_info({udp, Socket, Ip, Port, Packet}, #udp_acceptor{name = Name, socket = Socket} = State) ->
    TS = erlang:monotonic_time(),
    Task = {Socket, Ip, Port, TS, Packet},
    wpool:cast(Name, Task, random_worker),
    {noreply, State};
handle_info({udp_passive, Socket}, #udp_acceptor{socket = Socket} = State) ->
    %% TODO: implement some sort of backpressure
    inet:setopts(Socket, [{active, ?ACTIVE}]),
    {noreply, State};
handle_info({udp_error, Socket, Reason}, #udp_acceptor{socket = Socket} = State) ->
    {stop, {udp_error, Reason}, State};
handle_info(Info, State) ->
    ?LOG_INFO(#{what => unexpected_info, info => Info}),
    {noreply, State}.

-spec create_socket([gen_udp:open_option()]) -> inet:socket().
create_socket(Opts) ->
    case gen_udp:open(0, [{active, ?ACTIVE} | Opts]) of
        {ok, Socket} ->
            Socket;
        {error, Reason} ->
            exit({could_not_open_socket, Reason})
    end.
