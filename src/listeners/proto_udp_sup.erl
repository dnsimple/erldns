-module(proto_udp_sup).

-behaviour(supervisor).

-export([start_link/0]).
-export([init/1]).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, noargs).

init(noargs) ->
    proc_lib:set_label(?MODULE),
    SupFlags = #{strategy => one_for_one},
    Parallelism = erlang:system_info(schedulers),
    % StatsCounters = counters:new(2 * Parallelism, []),
    Spawn = children_option_spawn(Parallelism, 9999),
    WorkerPool = children_option_worker_pool(Parallelism, 8888),
    {ok, {SupFlags, Spawn ++ WorkerPool}}.

children_option_spawn(Parallelism, Port) ->
    [
        #{
            id => proto_udp_conns_sup_sup,
            start => {proto_udp_conns_sup_sup, start_link, [Parallelism]},
            type => supervisor
        },
        #{
            id => proto_udp_acceptors_sup,
            start => {proto_udp_acceptors_sup, start_link, [Parallelism, Port]},
            type => supervisor
        }
    ].

children_option_worker_pool(Parallelism, Port) ->
    WorkerSize = 10 * Parallelism,
    Ref = proto_worker_pool:new(WorkerSize),
    Skerl = ddskerl_counters:new(#{error => 0.01, bound => 2148}),
    persistent_term:put(ddskerl, Skerl),
    [
        #{
            id => proto_worker_pool_sup,
            start => {proto_worker_pool_sup, start_link, [WorkerSize, Ref, Skerl]},
            type => supervisor
        },
        #{
            id => proto_udp_wpool_acceptors_sup,
            start => {proto_udp_wpool_acceptors_sup, start_link, [Parallelism, Port, Ref]},
            type => supervisor
        }
    ].
