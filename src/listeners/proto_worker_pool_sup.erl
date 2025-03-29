-module(proto_worker_pool_sup).

-behaviour(supervisor).

-export([start_link/3]).

-export([init/1]).

start_link(WorkerSize, Ref, Skerl) ->
    supervisor:start_link(?MODULE, {WorkerSize, Ref, Skerl}).

init({WorkerSize, Ref, Skerl}) ->
    SupFlags = #{strategy => one_for_one},
    ChildSpecs = [
        #{
            id => {proto_worker_pool, Id},
            start => {proto_worker_pool, start_link, [{Ref, Id, Skerl}]},
            type => worker
        }
     || Id <- lists:seq(1, WorkerSize)
    ],
    {ok, {SupFlags, ChildSpecs}}.
