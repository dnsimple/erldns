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
  {ok, PgsqlPools} = application:get_env(erldns, pg_pool),
  PgsqlPoolSpecs = lists:map(fun({PoolName, PoolConfig, WorkerArgs}) ->
        PoolArgs = [{name, {local, PoolName}},
                    {worker_module, erldns_pgsql_worker}] ++ PoolConfig,
        poolboy:child_spec(PoolName, PoolArgs, WorkerArgs)
    end, PgsqlPools),

  Procs = [
    ?CHILD(erldns_packet_cache, worker, []),
    ?CHILD(erldns_query_throttle, worker, []),
    {udp_inet, {erldns_udp_server, start_link, [udp_inet, inet]}, permanent, 5000, worker, [erldns_udp_server]},
    {udp_inet6, {erldns_udp_server, start_link, [udp_inet6, inet6]}, permanent, 5000, worker, [erldns_udp_server]},
    {tcp_inet, {erldns_tcp_server, start_link, [tcp_inet, inet]}, permanent, 5000, worker, [erldns_tcp_server]},
    {tcp_inet6, {erldns_tcp_server, start_link, [tcp_inet6, inet6]}, permanent, 5000, worker, [erldns_tcp_server]}
  ],

  {ok, {{one_for_one, 20, 10}, Procs ++ AppPoolSpecs ++ PgsqlPoolSpecs}}.
