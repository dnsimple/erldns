-module(erldns_sup).
-behavior(supervisor).

% API
-export([start_link/0]).

% Supervisor hooks
-export([init/1]).

-define(SUPERVISOR, ?MODULE).

%% Helper macro for declaring children of supervisor
-define(CHILD(I, Type, Args), {I, {I, start_link, Args}, permanent, 5000, Type, [I]}).

%% Public API
start_link() ->
  supervisor:start_link({local, ?SUPERVISOR}, ?MODULE, []).

init(_Args) ->
  {ok, AppPools} = application:get_env(erldns, pools),
  AppPoolSpecs = lists:map(fun({PoolName, PoolConfig}) ->
        Args = [{name, {local, PoolName}},
                {worker_module, erldns_worker}]
              ++ PoolConfig,
        poolboy:child_spec(PoolName, Args)
    end, AppPools),

  SysProcs = [
    ?CHILD(erldns_events, worker, []),
    ?CHILD(erldns_zone_cache, worker, []),
    ?CHILD(erldns_zone_parser, worker, []),
    ?CHILD(erldns_packet_cache, worker, []),
    ?CHILD(erldns_query_throttle, worker, []),
    ?CHILD(erldns_handler, worker, []),

    ?CHILD(sample_custom_handler, worker, [])
  ],

  OptionalProcs = case application:get_env(erldns, zone_server) of
    {ok, _} -> [?CHILD(erldns_zoneserver_monitor, worker, [])];
    _ -> []
  end,

  {ok, {{one_for_one, 20, 10}, SysProcs ++ OptionalProcs ++ AppPoolSpecs}}.
