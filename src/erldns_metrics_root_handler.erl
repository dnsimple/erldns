-module(erldns_metrics_root_handler).

-export([init/3]).
-export([content_types_provided/2]).
-export([to_html/2, to_json/2, to_text/2]).

-export([filter_stats/1]).

init(_Transport, _Req, []) ->
  {upgrade, protocol, cowboy_rest}.

content_types_provided(Req, State) ->
  {[
      {<<"text/html">>, to_html},
      {<<"text/plain">>, to_text},
      {<<"application/json">>, to_json}
    ], Req, State}.

to_html(Req, State) ->
  {<<"erldns metrics">>, Req, State}.

to_text(Req, State) ->
  {<<"erldns metrics">>, Req, State}.

to_json(Req, State) ->
  Body = jsx:encode([{<<"erldns">>, 
        [
          {<<"metrics">>, erldns_app:metrics()},
          {<<"stats">>, filter_stats(erldns_app:stats())}
        ]
      }]),
  {Body, Req, State}.

% Functions to clean up the stats so they can be returned as JSON.
filter_stats(Stats) ->
  filter_stats(Stats, []).

filter_stats([], FilteredStats) ->
  FilteredStats;
filter_stats([{Name, Stats}|Rest], FilteredStats) ->
  filter_stats(Rest, FilteredStats ++ [{Name, filter_stat_set(Stats)}]).

filter_stat_set(Stats) ->
  filter_stat_set(Stats, []).

filter_stat_set([], FilteredStatSet) ->
  FilteredStatSet;
filter_stat_set([{percentile, Percentiles}|Rest], FilteredStatSet) ->
  filter_stat_set(Rest, FilteredStatSet ++ [{percentile, keys_to_strings(Percentiles)}]);
filter_stat_set([{histogram, _}|Rest], FilteredStatSet) ->
  filter_stat_set(Rest, FilteredStatSet);
filter_stat_set([Pair|Rest], FilteredStatSet) ->
  filter_stat_set(Rest, FilteredStatSet ++ [Pair]).

keys_to_strings(Pairs) ->
  lists:map(
    fun({K, V}) ->
        {list_to_binary(lists:flatten(io_lib:format("~p", [K]))), V}
    end, Pairs).
