-module(erldns_app).
-behavior(application).

% Application hooks
-export([start/2, stop/1]).

start(Type, Args) ->
  lager:info("~p:start(~p, ~p)", [?MODULE, Type, Args]),
  random:seed(erlang:now()),
  enable_metrics(),
  AppLink = erldns_sup:start_link(),
  erldns_zone_cache:load_zones(),
  AppLink.

stop(State) ->
  lager:info("~p:stop(~p)~n", [?MODULE, State]),
  ok.

enable_metrics() ->
  lager:info("~p:enabling metrics", [?MODULE]),
  folsom_metrics:new_histogram(packet_cache_hit, slide, 60),
  folsom_metrics:new_histogram(packet_cache_miss, slide, 60),
  folsom_metrics:new_histogram(pgsql_responder_lookup_time, slide, 60),
  lager:info("~p:metrics enabled", [?MODULE]),
  ok.
