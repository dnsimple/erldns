-module(erldns_server_sup).
-behavior(supervisor).

% API
-export([start_link/0]).

% Supervisor hooks
-export([init/1]).

-define(SUPERVISOR, ?MODULE).

%% Public API
start_link() ->
  supervisor:start_link({local, ?SUPERVISOR}, ?MODULE, []).

init(_Args) ->
  Procs = [
    {udp_inet, {erldns_udp_server, start_link, [udp_inet, inet]}, permanent, 5000, worker, [erldns_udp_server]},
    {udp_inet6, {erldns_udp_server, start_link, [udp_inet6, inet6]}, permanent, 5000, worker, [erldns_udp_server]},
    {tcp_inet, {erldns_tcp_server, start_link, [tcp_inet, inet]}, permanent, 5000, worker, [erldns_tcp_server]},
    {tcp_inet6, {erldns_tcp_server, start_link, [tcp_inet6, inet6]}, permanent, 5000, worker, [erldns_tcp_server]}
  ],

  {ok, {{one_for_one, 20, 10}, Procs}}.
