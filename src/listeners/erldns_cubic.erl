-module(erldns_cubic).
-moduledoc false.
%% It adapts the TCP CUBIC congestion control algorithm (RFC 8312)
%% to control the Admission Rate of the UDP Acceptors.
%%
%% Why this limits the rate: by hypotetically sleeping 1ms, even if work was instant and we ignore
%% its effect entirely, we can be sure we won't accept more than 1K batches per second for example.
%%
%% The core logic relies on the cubic function, defined over time `t`:
%% $$W(t)=C(t−K)^3 + Wmax$$
%%
%% - `W(t)`: The target rate at time `t`.
%% - `Wmax`: The rate where we last crashed (saturated the CPU).
%% - `K`: The time it should take to return to `Wmax`.
%%   - it is calculated using the formula $K = cubic_root(WMax*(1-beta_cubic)/C)$
%% - $t−K$: This term is:
%%   - negative when recovering,
%%   - zero at the plateau,
%%   - and positive when probing new limits.
%%
%% * Concave (Recovery): When (t−K) is negative, cubing it keeps it negative.
%%      This means the curve grows fast initially but slows down as it approaches the limit.
%%
%% * Convex (Probing): When (t−K) becomes positive, the curve starts bending upwards,
%%      accelerating in a polynomial fashion to find new capacity.

%% =============================================================================
%% Tuning Constants (Derived from RFC 8312 Standards)
%% =============================================================================

%% C: The Cubic Scaling Factor.
%% Determines the "aggressiveness" of the curve.
%% 0.4 is standard. Higher = steeper curve (faster recovery, less stability).
-define(C, 0.4).
%% Beta: Multiplicative Decrease Factor.
%% When we hit stress, we cut the rate to Rate * Beta.
%% TCP CUBIC uses 0.7. TCP Reno uses 0.5.
%% 0.7 is gentle braking. 0.5 is a hard stop.
-define(BETA, 0.7).
%% Never stop completely (1 batch/sec)
-define(MIN_RATE, 1.0).
%% =============================================================================
%% MAX_RATE (Batches Per Second)
%%
%% This cap determines the "Reaction Latency" of the Servo.
%% Because Erlang timers cannot reliably sleep for less than 1ms, any Rate > 1000
%% results in a 0ms sleep (Full Speed).
%%
%% A rate higher than 1000 acts as "Virtual Momentum" or a "Grace Period"
%% against transient stress spikes. We must shed this momentum before the brake
%% physically engages (i.e., before rate drops below 1000).
%%
%% Calculation for Scenario "React after 2 consecutive congestion events":
%%    Threshold = 1000.0 (1ms sleep)
%%    Beta      = 0.7
%%    Formula   = Threshold / (Beta * Beta)
%%    Result    = 1000 / 0.49 = 2040.8
%%
%% We set this to 2000.0.
%% - If Rate is 2000, Drop 1 -> 1400 (Still 0ms Sleep).
%% - If Stress persists, Drop 2 -> 980 (Brake Engages: 1ms Sleep).
%% =============================================================================
-define(MAX_RATE, 2000.0).

-record(cubic, {
    %% WMax: The "Ceiling". The rate at which we last experienced overload.
    %% We use this as the reference point for the cubic curve.
    w_max = 1000.0 :: float(),
    %% K: The Target Time (seconds).
    %% How long the algorithm calculates it *should* take to reach WMax again.
    %% Derived from the cubic root formula.
    k = 0.0 :: float(),
    %% Epoch Start: Timestamp when the last congestion event occurred.
    %% All 't' calculations are relative to this moment.
    epoch_start = erlang:monotonic_time() :: integer(),
    %% Current Rate: The actual output of the servo (Batches/Sec).
    %% Start at MAX_RATE (2000) for full speed initially. Built-in hysteresis:
    %% - Rate > 1000 = 0ms sleep (full speed)
    %% - First congestion: 2000 * 0.7 = 1400 (still 0ms sleep)
    %% - Second congestion: 1400 * 0.7 = 980 (now 1ms sleep - brake engages)
    current_rate = ?MAX_RATE :: float()
}).
-opaque cubic() :: #cubic{}.
-type time() :: non_neg_integer().
-type timestamp() :: integer().
-export_type([cubic/0, time/0, timestamp/0]).

-export([new/0, control/3]).

-spec new() -> cubic().
new() ->
    #cubic{}.

%% =============================================================================
%% Main Update Loop
%% =============================================================================
-spec control(Cubic :: cubic(), Now :: timestamp(), IsStressed :: boolean()) ->
    {SleepMs :: time(), Cubic :: cubic()}.
%% CASE 1: CONGESTION AVOIDANCE (Growth)
%% The system is healthy. We re-calculate the rate based on the curve.
control(#cubic{} = State, NowNative, false) when is_integer(NowNative) ->
    {0, cubic_update(State, NowNative)};
%% CASE 2: CONGESTION EVENT (Packet Drop Equivalent)
%% The system is overloaded. We must reduce load immediately.
control(#cubic{} = State, NowNative, true) when is_integer(NowNative) ->
    congestion_event(State, NowNative).

%% =============================================================================
%% Logic: Cubic Growth (Concave -> Plateau -> Convex)
%% =============================================================================
-spec cubic_update(cubic(), timestamp()) -> cubic().
cubic_update(State, NowNative) ->
    %% 1. Calculate precise Delta in NATIVE units
    DeltaNative = NowNative - State#cubic.epoch_start,
    %% 2. Convert Native Delta -> Float Seconds
    %% We perform this conversion once, right here, for the formula.
    %% erlang:convert_time_unit handles the hardware frequency scale.
    %% To get float seconds, we convert to microseconds first (standard int),
    %% then divide by 1,000,000.0.
    %% This fits in a Small Integer (fast) for any epoch < 36 years.
    NanoSecondsInt = erlang:convert_time_unit(DeltaNative, native, nanosecond),
    %% Division by 1.0e9 converts 1,500,250,123 ns -> 1.500250123 s
    T = NanoSecondsInt / 1.0e9,
    %% 3. The CUBIC Formula
    %% R(t) = C(t - K)^3 + WMax
    %% Delta = (t - K)
    %% If T < K: Delta is negative. Cubic is negative. We are below WMax (Concave).
    %% If T = K: Delta is zero. We are at WMax (Plateau).
    %% If T > K: Delta is positive. Cubic is positive. We are above WMax (Convex).
    Delta = T - State#cubic.k,
    %% Optimization: pre-calculate sign to handle cube of negative numbers correctly
    %% (Erlang math:pow/2 works fine with negatives for odd powers, usually)
    CubicTerm = ?C * math:pow(Delta, 3),
    RawRate = CubicTerm + State#cubic.w_max,
    %% Ensure we stay within physical sanity bounds.
    NewRate = max(?MIN_RATE, min(?MAX_RATE, RawRate)),
    State#cubic{current_rate = NewRate}.

%% =============================================================================
%% Logic: Congestion Event (Multiplicative Decrease)
%% =============================================================================
-spec congestion_event(cubic(), timestamp()) -> {time(), cubic()}.
congestion_event(#cubic{current_rate = CurrentRate} = State, NowNative) ->
    %% 1. Capture the Limit
    %% We hit a wall. The current rate was too high.
    %% We set WMax to the current rate (or slightly below).
    %% Note: We use max/2 to ensure we don't accidentally lock in a tiny WMax.
    WMax = max(?MIN_RATE, CurrentRate),
    %% 2. Calculate New Rate (Fast Reduction)
    %% Cut the rate by Beta (e.g., reduce to 70%).
    NewRate = max(?MIN_RATE, WMax * ?BETA),
    %% 3. Calculate K (The Recovery Period)
    %% We need to solve the cubic equation for t = 0 (start of epoch) to find K.
    %% Equation:  CurrentRate = C * (0 - K)^3 + WMax
    %% Rearranged: K = cbrt( (WMax - CurrentRate) / C )
    %% Since CurrentRate is (WMax * Beta), this simplifies to:
    %% K = cbrt( (WMax * (1 - Beta)) / C )
    DistanceToMax = WMax * (1.0 - ?BETA),
    K = math:pow(DistanceToMax / ?C, 1 / 3),
    NewState = State#cubic{
        w_max = WMax,
        k = K,
        epoch_start = NowNative,
        current_rate = NewRate
    },
    {get_sleep_time(NewRate), NewState}.

%% =============================================================================
%% The Actuator: Rate -> Sleep
%% =============================================================================
%% Converts the abstract "Batches Per Second" into physical "Milliseconds Sleep".
get_sleep_time(Rate) ->
    %% Formula: Period (T) = 1 / Frequency (f)
    %% Interval (ms) = 1000 / Rate
    Interval = 1000.0 / Rate,
    %% We use the "Conservative Approximation":
    %% Sleep = Interval.
    %% This assumes WorkTime is 0.
    %% Since WorkTime > 0, the ActualRate will be slightly lower than TargetRate.
    %% This provides a built-in safety margin against overshooting.
    %% Clamp logic:
    %% Min Sleep: 0ms (Full Speed)
    %% Max Sleep: 1000ms (Don't sleep forever, keep the servo ticking)
    round(max(0.0, min(1000.0, Interval))).
