-module(erldns_app).
-behavior(application).

% Application hooks
-export([start/2, stop/1]).

start(Type, Args) ->
  lager:info("~p:start(~p, ~p)~n", [?MODULE, Type, Args]),
  erldns_debugging:start(),
  erldns_sup:start_link().

stop(State) ->
  lager:info("~p:stop(~p)~n", [?MODULE, State]),
  ok.
