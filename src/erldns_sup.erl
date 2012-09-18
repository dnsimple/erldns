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
    ?CHILD(erldns_udp_server, worker, []),
    ?CHILD(erldns_tcp_server, worker, [])
  ],
  %% More than 20 failures in 10 seconds
  {ok, {{one_for_one, 20, 10}, Procs}}.
