-module(erldns_websocket_sup).
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
  WebsocketUrl = erldns_zone_client:websocket_url(),
  lager:debug("Connecting to web socket: ~p", [WebsocketUrl]),
  Procs = [
    {websocket_client, {websocket_client, start_link, [WebsocketUrl, erldns_zone_client, []]}, permanent, 5000, worker, []}
  ],

  {ok, {{one_for_one, 20, 10}, Procs}}.
