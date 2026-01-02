-module(erldns_codel).
-moduledoc false.
%% Inspired by
%% https://github.com/jlouis/safetyvalve/blob/master/src/sv_codel.erl
%% at commit c8235c6ca1deffeccdbba9dd74263408ed56594a
%%
%% This is a loose translation of the following link from ACM:
%% - https://datatracker.ietf.org/doc/html/rfc8289
%% - https://queue.acm.org/appendices/codel.html
%% - https://pollere.net/CoDelnotes.html

%% 5ms: Acceptable standing queue delay
-define(TARGET, 5).
%% 100ms: Rolling window to find the minimum
-define(INTERVAL, 100).
%% Logic proxy for "MTU size check" (1 item)
-define(MAX_PACKET, 1).
%% Interval slots for hysteresis, see where it is used
-define(HYSTERESIS_MULTIPLIER, 16).

-record(codel, {
    %% -- Estimator State (Tracking the Minimum) --
    %% First above time tracks when we first began seeing too much delay imposed by the queue.
    %% This value may be 0 in which case it means we have not seen such a delay.
    first_above_time = 0 :: timestamp(),
    %% -- Control Law State (The Dropping Schedule) --
    %% If we are dropping, this value tracks the point in time where the next packet
    %% should be dropped from the queue.
    drop_next_time = 0 :: timestamp(),
    %% This variable tracks how many packets/jobs were recently dropped from the queue.
    %% The value decays over time if no packets are dropped and is used to manipulate
    %% the control law of the queue.
    count = 0 :: integer(),
    %% The `dropping' field tracks if the CoDel system is in a dropping state or not.
    dropping = false :: boolean(),
    %% The `interval' and `target' are configurable parameters, described in @see init/2.
    interval :: time(),
    target :: time()
}).
-opaque codel() :: #codel{}.
-type interval() :: time().
-type target() :: time().
-type count() :: integer().
-type flag() :: continue | drop.
-type dodequeue_result() :: {flag(), codel()}.
-type time() :: non_neg_integer().
-type timestamp() :: integer().
-type sojourn_time() :: non_neg_integer().
-type queue_length() :: non_neg_integer().
-export_type([
    codel/0,
    interval/0,
    target/0,
    dodequeue_result/0,
    time/0,
    timestamp/0,
    queue_length/0
]).

-export([new/0, new/1, new/2, dequeue/4]).

-spec new() -> codel().
new() ->
    new(?INTERVAL, ?TARGET).

-spec new(interval()) -> codel().
new(Interval) ->
    Target = round(0.1 * Interval),
    new(Interval, Target).

-spec new(interval(), target()) -> codel().
new(Interval, Target) ->
    #codel{
        interval = erlang:convert_time_unit(Interval, millisecond, native),
        target = erlang:convert_time_unit(Target, millisecond, native)
    }.

%% https://datatracker.ietf.org/doc/html/rfc8289#section-5.5 Dequeue Routine
-spec dequeue(codel(), timestamp(), timestamp(), queue_length()) -> dodequeue_result().
dequeue(#codel{} = Codel, Now, IngressTimestamp, QueueLen) when
    is_integer(Now), is_integer(IngressTimestamp), is_integer(QueueLen)
->
    SojournTime = Now - IngressTimestamp,
    case dodequeue(Codel, Now, SojournTime, QueueLen) of
        %% sojourn time below TARGET - leave drop state
        {continue, #codel{dropping = true} = Codel1} ->
            {continue, Codel1#codel{dropping = false}};
        {drop, #codel{dropping = true} = Codel1} ->
            dequeue_drop_next(Codel1, Now);
        %% If we get here, we're not in drop state. The 'drop'
        %% return from dodequeue means that the sojourn time has been
        %% above 'TARGET' for 'INTERVAL', so enter drop state.
        {drop, #codel{dropping = false} = Codel1} ->
            dequeue_start_drop(Codel1, Now);
        %% Default case for normal operation.
        {continue, #codel{dropping = false} = Codel1} ->
            {continue, Codel1}
    end.

%% Time for the next drop.  Drop current packet and dequeue
%% next.  If the dequeue doesn't take us out of dropping
%% state, schedule the next drop.  A large backlog might
%% result in drop rates so high that the next drop should
%% happen now, hence the 'while' loop.
dequeue_drop_next(#codel{drop_next_time = DN, interval = Interval} = Codel, Now) when DN =< Now ->
    NewCount = Codel#codel.count + 1,
    {drop, Codel#codel{count = NewCount, drop_next_time = control_law(Now, Interval, NewCount)}};
dequeue_drop_next(#codel{} = Codel, _Now) ->
    {continue, Codel}.

%% If min went above TARGET close to when it last went
%% below, assume that the drop rate that controlled the
%% queue on the last cycle is a good starting point to
%% control it now.  ('drop_next' will be at most 'INTERVAL'
%% later than the time of the last drop, so 'now - drop_next'
%% is a good approximation of the time from the last drop
%% until now.) Implementations vary slightly here; this is
%% the Linux version, which is more widely deployed and
%% tested.
dequeue_start_drop(
    #codel{drop_next_time = LastDN, count = LastCount, interval = Interval} = Codel, Now
) when
    Now - LastDN < ?HYSTERESIS_MULTIPLIER * Interval, 2 < LastCount
->
    NewCount = LastCount - 2,
    {drop, Codel#codel{
        dropping = true,
        count = NewCount,
        drop_next_time = control_law(Now, Interval, NewCount)
    }};
dequeue_start_drop(#codel{interval = Interval} = Codel, Now) ->
    {drop, Codel#codel{
        dropping = true,
        count = 1,
        drop_next_time = control_law(Now, Interval, 1)
    }}.

%% https://datatracker.ietf.org/doc/html/rfc8289#section-5.6 Helper Routines

%% Since the degree of multiplexing and nature of the traffic sources is
%% unknown, CoDel acts as a closed-loop servo system that gradually
%% increases the frequency of dropping until the queue is controlled
%% (sojourn time goes below TARGET).  This is the control law that
%% governs the servo.  It has this form because of the sqrt(p)
%% dependence of TCP throughput on drop probability.
-spec control_law(timestamp(), interval(), count()) -> timestamp().
control_law(TS, Interval, 1) ->
    TS + Interval;
control_law(TS, Interval, Count) when 1 < Count ->
    TS + round(Interval / math:sqrt(Count)).

%% queue is empty - we can't be above TARGET
-spec dodequeue(codel(), timestamp(), sojourn_time(), queue_length()) -> dodequeue_result().
dodequeue(#codel{} = Codel, _Now, _SojournTime, 0) ->
    {continue, Codel#codel{first_above_time = 0}};
%% To span a large range of bandwidths, CoDel runs two
%% different AQMs in parallel.  One is based on sojourn time
%% and takes effect when the time to send an MTU-sized
%% packet is less than TARGET.  The 1st term of the "if"
%% below does this.  The other is based on backlog and takes
%% effect when the time to send an MTU-sized packet is >=
%% TARGET.  The goal here is to keep the output link
%% utilization high by never allowing the queue to get
%% smaller than the amount that arrives in a typical
%% interarrival time (MTU-sized packets arriving spaced
%% by the amount of time it takes to send such a packet on
%% the bottleneck).  The 2nd term of the "if" does this.
dodequeue(#codel{target = Target} = Codel, _Now, SojournTime, QueueLen) when
    SojournTime < Target andalso ?MAX_PACKET < QueueLen
->
    {continue, Codel#codel{first_above_time = 0}};
%% just went above from below. if still above at first_above_time, will say it's ok to drop.
dodequeue(#codel{first_above_time = 0} = Codel, Now, _SojournTime, _QueueLen) ->
    {continue, Codel#codel{first_above_time = Now + Codel#codel.interval}};
%% We have been above target for more than one interval. This is when we need to start dropping.
dodequeue(#codel{first_above_time = FAT} = Codel, Now, _SojournTime, _QueueLen) when FAT =< Now ->
    {drop, Codel};
%% We are above target, but we have not yet been above target for a complete interval.
%% Wait and see what happens, but don't begin dropping packets just yet.
dodequeue(#codel{} = Codel, _Now, _SojournTime, _QueueLen) ->
    {continue, Codel}.
