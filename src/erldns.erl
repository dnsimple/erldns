-module(erldns).

-behavior(application).
-behavior(supervisor).

% Application hooks
-export([start/2, stop/1]).

% Supervisor hooks
-export([init/1]).

%%% Application, this is a work-in-progress

start(_Type, _Args) ->
  supervisor:start_link().

stop(_State) ->
  ok.

%%% Supervisor

init([]) ->
   erldns_server:start(),
   {ok, {one_for_one, 5, 10}, []}.
