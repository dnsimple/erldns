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
  Procs = [
    ?CHILD(erldns_packet_cache, worker, []),
    {udp_inet, {erldns_udp_server, start_link, [udp_inet, inet]}, permanent, 5000, worker, [erldns_udp_server]},
    {udp_inet6, {erldns_udp_server, start_link, [udp_inet6, inet6]}, permanent, 5000, worker, [erldns_udp_server]}
  ],
  %% More than 20 failures in 10 seconds
  {ok, {{one_for_one, 20, 10}, Procs}}.
