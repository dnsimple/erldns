-module(erldns_async_pool).
-moduledoc false.

-behaviour(gen_server).

-include_lib("kernel/include/logger.hrl").

%% API
-export([cast/1, get_stats/0]).
%% worker pool details
-export([child_spec/0, overrun_handler/1]).
%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-define(LOG_METADATA, #{domain => [erldns, pipeline, async_pool]}).
-define(POOL_NAME, erldns_async_pool).
-define(DEFAULT_POOL_SIZE_MULTIPLIER, 4).
%% CoDel parameters for async pool (larger window for async work)
-define(DEFAULT_CODEL_INTERVAL_MS, 500).
%% How many drops before checking system messages
-define(DRAIN_BUDGET, 100).

-type task() :: {async_work, pid(), erldns_pipeline:continuation()}.
-type done() :: {async_done, erldns_pipeline:continuation()}.
-export_type([task/0, done/0]).

%% Returns the child spec for starting the async pool under a supervisor..
-spec child_spec() -> supervisor:child_spec().
child_spec() ->
    PipelineConfig = application:get_env(erldns, pipeline, #{}),
    Config = maps:get(async_pool, PipelineConfig, #{}),
    DefaultSize = erlang:system_info(schedulers) * ?DEFAULT_POOL_SIZE_MULTIPLIER,
    CodelInterval = maps:get(codel_interval, Config, ?DEFAULT_CODEL_INTERVAL_MS),
    DefaultCodelTarget = round(0.1 * CodelInterval),
    CodelTarget = maps:get(codel_target, Config, DefaultCodelTarget),
    Size = maps:get(parallelism, Config, DefaultSize),
    WorkerOpts = #{
        workers => Size,
        worker => {?MODULE, {CodelInterval, CodelTarget}},
        worker_shutdown => 5000,
        pool_sup_shutdown => infinity,
        strategy => #{
            strategy => one_for_one,
            intensity => 1 + ceil(math:log2(Size)),
            period => 5
        },
        overrun_warning => 5000,
        overrun_handler => [{?MODULE, overrun_handler}],
        max_overrun_warnings => 2,
        enable_queues => false
    },
    wpool:child_spec(?POOL_NAME, WorkerOpts).

%% Handler for overrun warnings (worker taking too long)..
-spec overrun_handler([{atom(), term()}, ...]) -> term().
overrun_handler(Args) ->
    ArgsMap = maps:from_list([{what, async_worker_overrun} | Args]),
    ?LOG_WARNING(ArgsMap, ?LOG_METADATA),
    telemetry:execute([erldns, request, timeout], #{count => 1}, ArgsMap).

%% Run the continuation's blocking work asynchronously.
%%
%% The worker sends the result via `gen_server:cast(ReplyToPid, {async_done, Result})` so the
%% requester handles it in handle_cast. This means it is expected the requester to be a gen_server
-spec cast(erldns_pipeline:continuation()) -> ok.
cast(Continuation) ->
    Work = {async_work, self(), Continuation},
    telemetry:execute([erldns, pipeline, suspend], #{count => 1}, #{cont => Continuation}),
    wpool:cast(?POOL_NAME, Work, random_worker).

%% Get pool status for monitoring..
-spec get_stats() -> erldns_listeners:stats().
get_stats() ->
    Stats = wpool:stats(?POOL_NAME),
    {_, TotalPool} = lists:keyfind(total_message_queue_len, 1, Stats),
    #{async => #{queue_length => TotalPool}}.

-doc false.
-spec init({non_neg_integer(), non_neg_integer()}) -> {ok, erldns_codel:codel()}.
init({CodelInterval, CodelTarget}) ->
    proc_lib:set_label(?MODULE),
    {ok, erldns_codel:new(CodelInterval, CodelTarget)}.

-doc false.
-spec handle_call(term(), gen_server:from(), erldns_codel:codel()) ->
    {reply, not_implemented, erldns_codel:codel()}.
handle_call(Call, From, Codel) ->
    ?LOG_INFO(#{what => unexpected_call, from => From, call => Call}, ?LOG_METADATA),
    {reply, not_implemented, Codel}.

-doc false.
-spec handle_cast(task(), erldns_codel:codel()) -> {noreply, erldns_codel:codel()}.
handle_cast({async_work, ReplyToPid, Continuation}, Codel) ->
    try
        process_work(Codel, ReplyToPid, Continuation, ?DRAIN_BUDGET)
    catch
        Class:Reason:Stacktrace ->
            ErrorMetadata = #{
                what => async_work_failed,
                class => Class,
                reason => Reason,
                stacktrace => Stacktrace
            },
            telemetry:execute([erldns, pipeline, error], #{count => 1}, ErrorMetadata),
            {noreply, Codel}
    end;
handle_cast(Cast, Codel) ->
    ?LOG_INFO(#{what => unexpected_cast, cast => Cast}, ?LOG_METADATA),
    {noreply, Codel}.

-doc false.
-spec handle_info(term(), erldns_codel:codel()) -> {noreply, erldns_codel:codel()}.
handle_info(Info, Codel) ->
    ?LOG_INFO(#{what => unexpected_info, info => Info}, ?LOG_METADATA),
    {noreply, Codel}.

-spec process_work(Codel, ReplyToPid, Continuation, Budget) -> Result when
    Codel :: erldns_codel:codel(),
    ReplyToPid :: pid(),
    Continuation :: erldns_pipeline:continuation(),
    Budget :: integer(),
    Result :: {noreply, erldns_codel:codel()}.
process_work(Codel, ReplyToPid, Continuation, Budget) ->
    Opts = erldns_pipeline:get_continuation_opts(Continuation),
    IngressTs = maps:get(monotonic_time, Opts),
    Now = erlang:monotonic_time(),
    {message_queue_len, QueueLen} = process_info(self(), message_queue_len),
    case erldns_codel:dequeue(Codel, Now, IngressTs, QueueLen) of
        {continue, Codel1} ->
            run_blocking_work_and_reply(ReplyToPid, Continuation),
            {noreply, Codel1};
        {drop, Codel1} ->
            telemetry:execute([erldns, request, dropped], #{count => 1}, #{}),
            drop_loop(Codel1, Budget)
    end.

-spec drop_loop(erldns_codel:codel(), non_neg_integer()) -> {noreply, erldns_codel:codel()}.
drop_loop(Codel, 0) ->
    {noreply, Codel};
drop_loop(Codel, Budget) ->
    receive
        {'$gen_cast', {async_work, ReplyToPid, Continuation}} ->
            process_work(Codel, ReplyToPid, Continuation, Budget - 1)
    after 0 ->
        {noreply, Codel}
    end.

-spec run_blocking_work_and_reply(ReplyToPid, Continuation) -> ok when
    ReplyToPid :: pid(),
    Continuation :: erldns_pipeline:continuation().
run_blocking_work_and_reply(ReplyToPid, Continuation) ->
    case erldns_pipeline:execute_work(Continuation) of
        halt ->
            ok;
        Continuation1 ->
            gen_server:cast(ReplyToPid, {async_done, Continuation1})
    end.
