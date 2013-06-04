-module(erldns_server_sup).
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
  ServerProcs = [
    {udp_inet, {erldns_udp_server, start_link, [udp_inet, inet]}, permanent, 5000, worker, [erldns_udp_server]},
    {udp_inet6, {erldns_udp_server, start_link, [udp_inet6, inet6]}, permanent, 5000, worker, [erldns_udp_server]},
    {tcp_inet, {erldns_tcp_server, start_link, [tcp_inet, inet]}, permanent, 5000, worker, [erldns_tcp_server]},
    {tcp_inet6, {erldns_tcp_server, start_link, [tcp_inet6, inet6]}, permanent, 5000, worker, [erldns_tcp_server]}
  ],

  CheckerProcs = [
    %?CHILD(erldns_zone_checker, worker, [])
  ],

  {ok, {{one_for_one, 20, 10}, ServerProcs ++ CheckerProcs}}.
