-module(erldns_proto_udp_acceptor).
-moduledoc false.

-include_lib("kernel/include/logger.hrl").

-define(ACTIVE, 100).
-define(STRESS_LIMIT, 9000).
% Jitter as percentage of sleep time (e.g., 0.15 = 15% variation)
% This gives ±7.5% jitter to break synchronization
-define(JITTER_PERCENT, 0.15).
-define(LOG_METADATA, #{domain => [erldns, listeners, udp]}).

-behaviour(gen_server).

-export([start_link/2, init/1, handle_call/3, handle_cast/2, handle_info/2]).

-record(udp_acceptor, {
    name :: atom(),
    socket :: gen_udp:socket(),
    servo = erldns_cubic:new() :: erldns_cubic:cubic()
}).
-opaque state() :: #udp_acceptor{}.
-export_type([state/0]).

-spec start_link(erldns_listeners:name(), [gen_udp:option()]) ->
    gen_server:start_ret().
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
    ?LOG_INFO(#{what => unexpected_call, from => From, call => Call}, ?LOG_METADATA),
    {reply, not_implemented, State}.

-spec handle_cast(term(), state()) -> {noreply, state()}.
handle_cast(Cast, State) ->
    ?LOG_INFO(#{what => unexpected_cast, cast => Cast}, ?LOG_METADATA),
    {noreply, State}.

-spec handle_info(term(), state()) -> {noreply, state()} | {stop, term(), state()}.
handle_info({udp, Socket, Ip, Port, Packet}, #udp_acceptor{name = Name, socket = Socket} = State) ->
    TS = erlang:monotonic_time(),
    Task = {udp_work, Socket, Ip, Port, TS, Packet},
    wpool:cast(Name, Task, random_worker),
    {noreply, State};
handle_info({udp_passive, Socket}, #udp_acceptor{socket = Socket} = State) ->
    maybe_shed_load(Socket, State);
handle_info({udp_error, Socket, Reason}, #udp_acceptor{socket = Socket} = State) ->
    {stop, {udp_error, Reason}, State};
handle_info({set_batch, Socket}, #udp_acceptor{socket = Socket} = State) ->
    set_batch(Socket),
    {noreply, State};
handle_info(Info, State) ->
    ?LOG_INFO(#{what => unexpected_info, info => Info}, ?LOG_METADATA),
    {noreply, State}.

-spec create_socket([gen_udp:open_option()]) -> inet:socket().
create_socket(Opts) ->
    case gen_udp:open(0, [{active, ?ACTIVE} | Opts]) of
        {ok, Socket} ->
            Socket;
        {error, Reason} ->
            exit({could_not_open_socket, Reason})
    end.

maybe_shed_load(Socket, #udp_acceptor{servo = Servo} = State) ->
    Now = erlang:monotonic_time(),
    Utilization = erldns_sch_mon:get_total_scheduler_utilization(),
    IsCongested = ?STRESS_LIMIT < Utilization,
    {SleepMs, NewServo} = erldns_cubic:control(Servo, Now, IsCongested),
    case SleepMs of
        0 ->
            set_batch(Socket);
        _ ->
            telemetry:execute([erldns, request, delayed], #{count => 1}, #{transport => udp}),
            FinalSleep = calculate_jittered_sleep(SleepMs),
            set_batch_after_timer(Socket, FinalSleep)
    end,
    {noreply, State#udp_acceptor{servo = NewServo}}.

calculate_jittered_sleep(SleepMs) ->
    % Apply proportional jitter to break synchronization
    % Jitter range: ±JITTER_PERCENT/2 of sleep time
    % Example: If SleepMs=100ms and JITTER_PERCENT=0.15, jitter is ±7.5ms
    JitterRange = SleepMs * ?JITTER_PERCENT,
    Jitter = (rand:uniform() - 0.5) * JitterRange,
    TotalSleep = SleepMs + Jitter,
    % Clamp to reasonable range (1ms minimum, 1000ms maximum)
    max(1, min(1000, round(TotalSleep))).

-spec set_batch_after_timer(gen_udp:socket(), non_neg_integer()) -> reference().
set_batch_after_timer(Socket, SleepMs) ->
    erlang:send_after(SleepMs, self(), {set_batch, Socket}).

set_batch(Socket) ->
    inet:setopts(Socket, [{active, ?ACTIVE}]).
