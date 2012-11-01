-module(erldns_app).
-behavior(application).

% Application hooks
-export([start/2, stop/1]).

start(Type, Args) ->
  lager:info("~p:start(~p, ~p)", [?MODULE, Type, Args]),
  random:seed(erlang:now()),
  optionally_start_debugger(),
  enable_metrics(),
  erldns_sup:start_link().

stop(State) ->
  lager:info("~p:stop(~p)~n", [?MODULE, State]),
  ok.

optionally_start_debugger() ->
  case application:get_env(erldns, debugger) of
    {ok, true} -> erldns_debugging:start();
    _ -> ok
  end.

enable_metrics() ->
  lager:info("~p:enabling metrics", [?MODULE]),
  folsom_metrics:new_histogram(packet_cache_hit, slide, 60),
  folsom_metrics:new_histogram(packet_cache_miss, slide, 60),
  folsom_metrics:new_histogram(mysql_responder_lookup_time, slide, 60),
  lager:info("~p:metrics enabled", [?MODULE]),
  ok.
