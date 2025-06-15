-module(erldns_proto_udp_acceptor).
-moduledoc false.

-include_lib("kernel/include/logger.hrl").

-define(ACTIVE, 100).

-behaviour(gen_server).

-export([start_link/2, init/1, handle_call/3, handle_cast/2, handle_info/2]).

-record(udp_acceptor, {
    name :: atom(),
    socket :: gen_udp:socket()
}).
-type state() :: #udp_acceptor{}.

-spec start_link(erldns_listeners:name(), [gen_udp:option()]) -> gen_server:start_ret().
start_link(Name, SocketOpts) ->
    gen_server:start_link(?MODULE, {Name, SocketOpts}, []).

-spec init({atom(), [gen_udp:open_option()]}) -> {ok, state()}.
init({Name, SocketOpts}) ->
    process_flag(trap_exit, true),
    proc_lib:set_label(?MODULE),
    Socket = create_socket(SocketOpts),
    {ok, #udp_acceptor{name = Name, socket = Socket}}.

-spec handle_call(term(), gen_server:from(), state()) -> {reply, not_implemented, state()}.
handle_call(Call, From, State) ->
    ?LOG_INFO(#{what => unexpected_call, from => From, call => Call}),
    {reply, not_implemented, State}.

-spec handle_cast(term(), state()) -> {noreply, state()}.
handle_cast(Cast, State) ->
    ?LOG_INFO(#{what => unexpected_cast, cast => Cast}),
    {noreply, State}.

-spec handle_info(term(), state()) -> {noreply, state()} | {stop, term(), state()}.
handle_info({udp, Socket, Ip, Port, Packet}, #udp_acceptor{name = Name, socket = Socket} = State) ->
    TS = erlang:monotonic_time(),
    Task = {Socket, Ip, Port, TS, Packet},
    wpool:cast(Name, Task, random_worker),
    {noreply, State};
handle_info({udp_passive, Socket}, #udp_acceptor{socket = Socket} = State) ->
    maybe_shed_load(Socket, State);
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

%% If scheduler utilisation is above 90%, probabilistically,
%% introduce delays before activating the socket again.
%%
%% A scheduler utilisation near 100% means that processes might face a long delay before being
%% scheduled again and we might start entering a death spiral were requests are queued only to be
%% ignored because of delays. If probabilistically we don't accept any more requests, the Kernel's
%% network stack will start dropping packets without having them enter the BEAM and incurr more CPU
%% waste in loops and GCs.
%%
%% probabilistic delay is proportional to the remaining free utilisation, that is,
%% - if utilisation is 92%, we have a 20% chance of delaying,
%% - if utilisation is 95%, we have a 50% chance of delaying.
%% - if utilisation is 96.23%, we have a 60.23% chance of delaying.
%% - if utilisation is 100%, we have a 100% chance of delaying.
%%
%% The operation will be retried again after `ingress_udp_request_timeout`, again calculating
%% utilisation and probabilistic delay accordingly.
maybe_shed_load(Socket, State) ->
    maybe
        Utilization = erldns_sch_mon:get_total_scheduler_utilization(),
        false ?= Utilization =< 9000,
        false ?= maybe_continue(Utilization),
        ?LOG_WARNING(#{what => udp_acceptor_delayed, transport => udp}),
        telemetry:execute([erldns, request, delayed], #{count => 1}, #{transport => udp}),
        start_timer(Socket),
        {noreply, State}
    else
        true ->
            inet:setopts(Socket, [{active, ?ACTIVE}]),
            {noreply, State}
    end.

-spec maybe_continue(erldns_sch_mon:percentage_double_point()) -> boolean().
maybe_continue(Utilization) when 9000 < Utilization, Utilization =< 10000 ->
    Dec = (Utilization - 9000) * 1000,
    Rand = rand:uniform(10000),
    Rand > Dec.

-spec start_timer(gen_udp:socket()) -> reference().
start_timer(Socket) ->
    Timeout = erldns_config:ingress_udp_request_timeout(),
    erlang:send_after(Timeout, self(), {udp_passive, Socket}).
