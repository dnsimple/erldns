-module(erldns_sup).
-behavior(supervisor).

% API
-export([start_link/0]).

% Supervisor hooks
-export([init/1]).

-define(SUPERVISOR, ?MODULE).

start_link() ->
  supervisor:start_link({local, ?SUPERVISOR}, ?MODULE, []).

init(_Args) ->
  Procs = [
    {erldns_server, {erldns_server, start_link, []},
      permanent, 5000, worker, [erldns_server]}
  ],
  {ok, {{one_for_one, 5, 10}, Procs}}.
