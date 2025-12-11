-module(erldns_zone_loader_worker_sup).
-moduledoc false.

-behaviour(supervisor).

-export([start_child/1]).
-export([start_link/0, init/1]).

-spec start_child([dynamic()]) -> supervisor:startchild_ret().
start_child(Args) ->
    supervisor:start_child(?MODULE, Args).

-spec start_link() -> supervisor:startlink_ret().
start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, noargs).

-spec init(noargs) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init(noargs) ->
    SupFlags = #{strategy => simple_one_for_one},
    WorkerSpec = file_worker_specs(),
    {ok, {SupFlags, [WorkerSpec]}}.

-spec file_worker_specs() -> supervisor:child_spec().
file_worker_specs() ->
    #{
        id => undefined,
        start => {erldns_zone_loader_worker, start_link, []},
        type => worker,
        restart => transient
    }.
