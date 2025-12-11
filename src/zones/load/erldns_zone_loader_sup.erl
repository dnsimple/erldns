-module(erldns_zone_loader_sup).
-moduledoc false.

-behaviour(supervisor).

-export([start_link/0, init/1]).

-spec start_link() -> supervisor:startlink_ret().
start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, noargs).

-spec init(noargs) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init(noargs) ->
    SupFlags = #{strategy => one_for_one, intensity => 10, period => 5},
    Config = erldns_zone_loader:get_config(),
    FileWorkerSupSpec = file_worker_sup_spec(),
    FileGetterSpec = file_getter_spec(Config),
    Children = [FileWorkerSupSpec, FileGetterSpec],
    {ok, {SupFlags, Children}}.

-spec file_worker_sup_spec() -> supervisor:child_spec().
file_worker_sup_spec() ->
    #{
        id => erldns_zone_loader_worker_sup,
        start => {erldns_zone_loader_worker_sup, start_link, []},
        type => supervisor,
        restart => permanent
    }.

-spec file_getter_spec(erldns_zones:config()) -> supervisor:child_spec().
file_getter_spec(Config) ->
    #{
        id => erldns_zone_loader_getter,
        start => {erldns_zone_loader_getter, start_link, [Config]},
        type => worker,
        restart => permanent
    }.
