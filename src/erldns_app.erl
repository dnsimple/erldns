-module(erldns_app).
-behavior(application).

% Application hooks
-export([start/2, start_phase/3, stop/1]).

-export([metrics/0, stats/0]).

start(_Type, _Args) ->
  define_metrics(),
  random:seed(erlang:now()),
  erldns_sup:start_link().

start_phase(post_start, _StartType, _PhaseArgs) ->
  case application:get_env(erldns, custom_zone_parsers) of
    {ok, Parsers} -> erldns_zone_parser:register_parsers(Parsers);
    _ -> ok
  end,

  lager:info("Loading zones from local file"),
  erldns_zone_loader:load_zones(),

  case application:get_env(erldns, zone_server) of
    {ok, _} ->
      lager:info("Loading zones from remote server"),
      erldns_zoneserver_monitor:fetch_zones(),
      lager:info("Zone loading complete"),
      lager:info("Websocket monitor connecting"),
      erldns_zoneserver_monitor:connect(),
      ok;
    _ ->
      not_fetching
  end,

  erldns_events:add_handler(erldns_event_logger),

  % Start up the UDP and TCP servers now
  erldns_server_sup:start_link(),

  erldns_events:notify(servers_started),

  ok.

stop(_State) ->
  lager:info("Stop erldns application"),
  ok.

metrics() ->
  lists:map(
    fun(Name) ->
        {Name, folsom_metrics:get_metric_value(Name)}
    end, folsom_metrics:get_metrics()).

stats() ->
  Histograms = [udp_handoff_histogram, tcp_handoff_histogram, request_handled_histogram],
  lists:map(
    fun(Name) ->
        {Name, folsom_metrics:get_histogram_statistics(Name)}
    end, Histograms).

define_metrics() ->
  folsom_metrics:new_histogram(udp_handoff_histogram),
  folsom_metrics:new_histogram(tcp_handoff_histogram),

  folsom_metrics:new_counter(request_throttled_counter),
  folsom_metrics:new_meter(request_throttled_meter),
  folsom_metrics:new_histogram(request_handled_histogram),

  folsom_metrics:new_meter(cache_hit_meter),
  folsom_metrics:new_meter(cache_expired_meter),
  folsom_metrics:new_meter(cache_miss_meter),

  folsom_metrics:get_metrics().
