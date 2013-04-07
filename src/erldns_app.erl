-module(erldns_app).
-behavior(application).

% Application hooks
-export([start/2, start_phase/3, stop/1]).

start(Type, Args) ->
  lager:info("~p:start(~p, ~p)", [?MODULE, Type, Args]),
  random:seed(erlang:now()),
  enable_metrics(),
  erldns_sup:start_link().

start_phase(post_start, _StartType, _PhaseArgs) ->
  case application:get_env(erldns, custom_zone_parsers) of
    {ok, Parsers} -> erldns_zone_parser:register_parsers(Parsers);
    _ -> ok
  end,

  lager:info("Loading zones from local file"),
  erldns_metrics:measure(none, erldns_zone_loader, load_zones, []),
  case application:get_env(erldns, zone_server) of
    {ok, _} ->
      lager:info("Loading zones from remote server"),
      erldns_metrics:measure(none, erldns_zone_client, fetch_zones, []),
      lager:info("Zone loading complete");
    _ -> not_fetching
  end,

  % Start up the UDP and TCP servers now
  erldns_server_sup:start_link(),

  ok.

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
