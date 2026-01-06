-module(erldns_sch_mon).
-moduledoc false.
%% This server keeps track of the normal schedulers utilisation.
%% It uses `erlang:statistics(scheduler_wall_time)` and then drops information related to dirty
%% schedulers, as they are not relevant for us. It then builds an average usage even taking into
%% consideration the number of schedulers that are online and offline, and stores in a public
%% atomics array the usage as a percentage with two decimal points, as an integer.
%%
%% It uses a 100ms update interval with Exponential Moving Average (EMA) smoothing.
%% This provides smooth, responsive utilization estimates.

-include_lib("kernel/include/logger.hrl").
-define(TOTAL_POS, 1).

-behaviour(gen_server).

-export([get_total_scheduler_utilization/0]).

-export([start_link/0, init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-record(sch_mon_state, {
    atomics_ref :: atomics:atomics_ref(),
    timer_ref :: reference(),
    last_sample :: scheduler_wall_time(),
    utilisation :: float(),
    % Previous interval used
    last_interval :: integer()
}).
-opaque state() :: #sch_mon_state{}.
-type scheduler_wall_time() :: [{pos_integer(), non_neg_integer(), non_neg_integer()}].
-type stress() :: 0..10000.
-export_type([state/0, stress/0]).

-define(LOG_METADATA, #{domain => [erldns, listeners]}).

% EMA smoothing factor (alpha = 0.3 means 30% weight to new sample, 70% to history)
-define(EMA_ALPHA, 0.3).

% Update interval: 100ms => Nyquist-Shannon Sampling Theorem
% The theorem states a simple but rigid condition: to perfectly reconstruct a signal from its
% samples, you must sample it at a rate greater than twice its highest frequency component.
-define(BASE_INTERVAL, 100).
% Minimum interval: 40ms (25 Hz max sampling)
-define(MIN_INTERVAL, 40).
% Maximum interval: 200ms (5 Hz min sampling)
-define(MAX_INTERVAL, 200).
% Controls sensitivity (lower = more sensitive)
-define(SCALE, 200).

%% We get here percentage with two decimal places as an integer.
-spec get_total_scheduler_utilization() -> stress().
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
    erlang:system_flag(scheduler_wall_time, true),
    S0 = get_scheduler_wall_time(),
    AtomicsRef = atomics:new(?TOTAL_POS, []),
    persistent_term:put(?MODULE, AtomicsRef),
    TimerRef = start_timer(?BASE_INTERVAL),
    S1 = get_scheduler_wall_time(),
    NewEMA = utilization(AtomicsRef, S0, S1, +0.0),
    {ok, #sch_mon_state{
        timer_ref = TimerRef,
        last_sample = S1,
        atomics_ref = AtomicsRef,
        utilisation = NewEMA,
        last_interval = ?BASE_INTERVAL
    }}.

-spec handle_call(sync, gen_server:from(), state()) ->
    {reply, ok | not_implemented, state()}.
handle_call(Call, From, State) ->
    ?LOG_INFO(#{what => unexpected_call, from => From, call => Call}, ?LOG_METADATA),
    {reply, not_implemented, State}.

-spec handle_cast(dynamic(), state()) -> {noreply, state()}.
handle_cast(Cast, State) ->
    ?LOG_INFO(#{what => unexpected_cast, cast => Cast}, ?LOG_METADATA),
    {noreply, State}.

-spec handle_info(dynamic(), state()) -> {noreply, state()}.
handle_info(
    {timeout, TimerRef, check_schedulers},
    #sch_mon_state{
        timer_ref = TimerRef,
        last_sample = S0,
        atomics_ref = AtomicsRef,
        utilisation = LastEma,
        last_interval = LastInterval
    } = State
) ->
    S1 = get_scheduler_wall_time(),
    NewEMA = utilization(AtomicsRef, S0, S1, LastEma),
    NewInterval = calculate_adaptive_interval(NewEMA, LastEma, LastInterval),
    NewTimerRef = start_timer(NewInterval),
    {noreply, State#sch_mon_state{
        timer_ref = NewTimerRef,
        last_sample = S1,
        utilisation = NewEMA,
        % Update for next calculation
        last_interval = NewInterval
    }};
handle_info(Info, State) ->
    ?LOG_INFO(#{what => unexpected_info, info => Info}, ?LOG_METADATA),
    {noreply, State}.

-spec terminate(term(), state()) -> term().
terminate(_, _) ->
    persistent_term:erase(?MODULE).

-spec calculate_adaptive_interval(float(), float(), integer()) -> integer().
calculate_adaptive_interval(CurrentUtil, LastUtil, LastInterval) ->
    %% Calculate rate of change (percentage points per second)
    DeltaUtil = abs(CurrentUtil - LastUtil),
    RateOfChange = 100000.0 * DeltaUtil / LastInterval,
    %% - DeltaUtil is fractional (0.0-1.0), convert to percentage points: * 100
    %% - LastInterval is in milliseconds, convert to seconds: / 1000
    %% Determine interval based on rate of change
    %% Inverse function: smooth, asymptotic behavior
    %% As rate → 0: interval → MAX (200ms)
    %% As rate → ∞: interval → MIN (40ms)
    Interval = ?MIN_INTERVAL + ((?MAX_INTERVAL - ?MIN_INTERVAL) / (1.0 + RateOfChange / ?SCALE)),
    %% Clamp to valid range
    max(?MIN_INTERVAL, min(?MAX_INTERVAL, round(Interval))).

-spec start_timer(non_neg_integer()) -> reference().
start_timer(Interval) ->
    erlang:start_timer(Interval, self(), check_schedulers).

-spec get_scheduler_wall_time() -> scheduler_wall_time().
get_scheduler_wall_time() ->
    S0 = erlang:statistics(scheduler_wall_time),
    true = undefined =/= S0,
    Online = erlang:system_info(schedulers_online),
    lists:sublist(lists:sort(S0), Online).

-spec utilization(atomics:atomics_ref(), scheduler_wall_time(), scheduler_wall_time(), float()) ->
    float().
utilization(AtomicsRef, S0, S1, LastEma) ->
    %% Calculate instant utilization from scheduler wall time
    {A, T} = lists:foldl(
        fun({{_, A0, T0}, {_, A1, T1}}, {Ai, Ti}) ->
            {Ai + (A1 - A0), Ti + (T1 - T0)}
        end,
        {0, 0},
        lists:zip(S0, S1)
    ),
    InstantUtil = safe_div(A, T),
    %% Apply EMA smoothing
    NewEMA = (?EMA_ALPHA * InstantUtil) + ((1.0 - ?EMA_ALPHA) * LastEma),
    %% Store EMA value in atomics (as percentage with two decimal places, as integer)
    PercentageTotal = round(10000 * NewEMA),
    atomics:put(AtomicsRef, ?TOTAL_POS, PercentageTotal),
    NewEMA.

-spec safe_div(number(), number()) -> float().
safe_div(_, Zero) when 0 == Zero ->
    +0.0;
safe_div(A, B) ->
    A / B.
