-module(erldns_sch_mon).
-moduledoc false.
%% This server keeps track of the normal schedulers utilisation.
%% It uses `erlang:statistics(scheduler_wall_time)` and then drops information related to dirty
%% schedulers, as they are not relevant for us. It then builds an average usage even taking into
%% consideration the number of schedulers that are online and offline, and stores in a public
%% atomics array the usage as a percentage with two decimal points, as an integer.
%%
%% It has a 1s tick.

-include_lib("kernel/include/logger.hrl").
-define(TOTAL_POS, 1).

-behaviour(gen_server).

-export([get_total_scheduler_utilization/0]).

-export([start_link/0, init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-type scheduler_wall_time() :: [{pos_integer(), non_neg_integer(), non_neg_integer()}].
-type state() :: {reference(), dynamic(), atomics:atomics_ref()}.
-type percentage_double_point() :: 0..10000.
-export_type([percentage_double_point/0, state/0]).

%% We get here percentage with two decimal places as an integer.
-spec get_total_scheduler_utilization() -> percentage_double_point().
get_total_scheduler_utilization() ->
    AtomicsRef = persistent_term:get(?MODULE),
    atomics:get(AtomicsRef, ?TOTAL_POS).

-spec start_link() -> gen_server:start_ret().
start_link() ->
    %% Priority is high so that on timer ticks it is always scheduled before any other regular
    %% process and it is not therefore delayed by long scheduler queues.
    SpawnOpts = [{spawn_opt, [{priority, high}]}],
    gen_server:start_link({local, ?MODULE}, ?MODULE, noargs, SpawnOpts).

-spec init(noargs) -> {ok, state()}.
init(noargs) ->
    process_flag(trap_exit, true),
    AtomicsRef = atomics:new(?TOTAL_POS, []),
    persistent_term:put(?MODULE, AtomicsRef),
    erlang:system_flag(scheduler_wall_time, true),
    S0 = get_scheduler_wall_time(),
    TimerRef = start_timer(),
    {ok, {TimerRef, S0, AtomicsRef}}.

-spec handle_call(sync, gen_server:from(), state()) ->
    {reply, ok | not_implemented, state()}.
handle_call(Call, From, State) ->
    ?LOG_INFO(
        #{what => unexpected_call, from => From, call => Call},
        #{domain => [erldns, listeners]}
    ),
    {reply, not_implemented, State}.

-spec handle_cast(dynamic(), state()) -> {noreply, state()}.
handle_cast(Cast, State) ->
    ?LOG_INFO(#{what => unexpected_cast, cast => Cast}, #{domain => [erldns, listeners]}),
    {noreply, State}.

-spec handle_info(dynamic(), state()) -> {noreply, state()}.
handle_info({timeout, TimerRef, check_schedulers}, {TimerRef, S0, AtomicsRef}) ->
    NewTimerRef = start_timer(),
    S1 = get_scheduler_wall_time(),
    utilization(AtomicsRef, S0, S1),
    {noreply, {NewTimerRef, S1, AtomicsRef}};
handle_info(Info, State) ->
    ?LOG_INFO(#{what => unexpected_info, info => Info}, #{domain => [erldns, listeners]}),
    {noreply, State}.

-spec terminate(term(), state()) -> any().
terminate(_, _) ->
    persistent_term:erase(?MODULE).

-spec start_timer() -> reference().
start_timer() ->
    erlang:start_timer(1000, self(), check_schedulers).

-spec get_scheduler_wall_time() -> scheduler_wall_time().
get_scheduler_wall_time() ->
    S0 = erlang:statistics(scheduler_wall_time),
    true = undefined =/= S0,
    Online = erlang:system_info(schedulers_online),
    lists:sublist(lists:sort(S0), Online).

-spec utilization(atomics:atomics_ref(), scheduler_wall_time(), scheduler_wall_time()) -> ok.
utilization(AtomicsRef, S0, S1) ->
    {A, T} = lists:foldl(
        fun({{_, A0, T0}, {_, A1, T1}}, {Ai, Ti}) ->
            {Ai + (A1 - A0), Ti + (T1 - T0)}
        end,
        {0, 0},
        lists:zip(S0, S1)
    ),
    Total = safe_div(A, T),
    PercentageTotal = round(10000 * Total),
    atomics:put(AtomicsRef, ?TOTAL_POS, PercentageTotal).

-spec safe_div(number(), number()) -> float().
safe_div(_, Zero) when 0 == Zero ->
    +0.0;
safe_div(A, B) ->
    A / B.
