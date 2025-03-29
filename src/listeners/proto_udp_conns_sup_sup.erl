-module(proto_udp_conns_sup_sup).

-behaviour(supervisor).

-export([start_link/1]).
-export([init/1]).

start_link(Parallelism) ->
    supervisor:start_link(?MODULE, Parallelism).

-spec init(pos_integer()) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init(Parallelism) ->
    proc_lib:set_label(?MODULE),
    StatsCounters = counters:new(2 * Parallelism, []),
    ets:insert(erldns_listener, {counters, StatsCounters}),
    ChildSpecs = [
        #{
            id => {proto_udp_conns_sup, Id},
            start => {proto_udp_conns_sup, start_link, [StatsCounters, Id]},
            type => supervisor
        }
     || Id <- lists:seq(1, Parallelism)
    ],
    {ok, {#{intensity => 1 + ceil(math:log2(Parallelism))}, ChildSpecs}}.
