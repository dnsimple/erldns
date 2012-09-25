-module(erldns_app).
-behavior(application).

% Application hooks
-export([start/2, stop/1]).

start(Type, Args) ->
  lager:info("~p:start(~p, ~p)~n", [?MODULE, Type, Args]),
  random:seed(erlang:now()),
  optionally_start_debugger(),
  erldns_sup:start_link().

stop(State) ->
  lager:info("~p:stop(~p)~n", [?MODULE, State]),
  ok.

optionally_start_debugger() ->
  case application:get_env(erldns, debugger) of
    {ok, true} -> erldns_debugging:start();
    _ -> ok
  end.
