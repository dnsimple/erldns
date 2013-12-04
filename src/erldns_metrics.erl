%% Copyright (c) 2012-2013, Aetrion LLC
%%
%% Permission to use, copy, modify, and/or distribute this software for any
%% purpose with or without fee is hereby granted, provided that the above
%% copyright notice and this permission notice appear in all copies.
%%
%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
%% WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
%% MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
%% ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
%% WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
%% ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
%% OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

%% @doc gen server that provides access to metrics recorded through Folsom.
-module(erldns_metrics).

-behavior(gen_server).

-export([start_link/0]).

-export([setup/0, metrics/0, stats/0, vm/0, ets/0, process_metrics/0, filtered_metrics/0, filtered_stats/0, filtered_vm/0, filtered_ets/0, filtered_process_metrics/0]).

-define(DEFAULT_PORT, 8082).

% Gen server hooks
-export([init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3
  ]).

-record(state, {}).

%% Not part of gen server

setup() ->
  folsom_metrics:new_counter(udp_request_counter),
  folsom_metrics:new_counter(tcp_request_counter),
  folsom_metrics:new_meter(udp_request_meter),
  folsom_metrics:new_meter(tcp_request_meter),

  folsom_metrics:new_histogram(udp_handoff_histogram),
  folsom_metrics:new_histogram(tcp_handoff_histogram),

  folsom_metrics:new_counter(request_throttled_counter),
  folsom_metrics:new_meter(request_throttled_meter),
  folsom_metrics:new_histogram(request_handled_histogram),

  folsom_metrics:new_counter(packet_dropped_empty_queue_counter),
  folsom_metrics:new_meter(packet_dropped_empty_queue_meter),

  folsom_metrics:new_meter(cache_hit_meter),
  folsom_metrics:new_meter(cache_expired_meter),
  folsom_metrics:new_meter(cache_miss_meter),

  folsom_metrics:new_history(load_remote_zones_history),

  folsom_metrics:new_meter(websocket_connection_terminated_meter),
  folsom_metrics:new_meter(websocket_connection_refused_meter),
  folsom_metrics:new_meter(websocket_connection_failed_meter),
  folsom_metrics:new_meter(websocket_connection_closed_meter),
  folsom_metrics:new_meter(websocket_connection_error_meter),

  folsom_metrics:new_meter(fetch_zones_error_meter),

  folsom_metrics:get_metrics().

metrics() ->
  lists:map(
    fun(Name) ->
        {Name, folsom_metrics:get_metric_value(Name)}
    end, folsom_metrics:get_metrics()).

filtered_metrics() ->
  filter_metrics(metrics()).

stats() ->
  Histograms = [udp_handoff_histogram, tcp_handoff_histogram, request_handled_histogram],
  lists:map(
    fun(Name) ->
        {Name, folsom_metrics:get_histogram_statistics(Name)}
    end, Histograms).

filtered_stats() ->
  filter_stats(stats()).

% Functions to clean up metrics so they can be returned as JSON.
filter_metrics(Metrics) ->
  filter_metrics(Metrics, []).

filter_metrics([], FilteredMetrics) ->
  FilteredMetrics;
filter_metrics([{Name, History = [{Timestamp, _Values}|_Rest]}|Rest], FilteredMetrics) when is_number(Timestamp) ->
  filter_metrics(Rest, FilteredMetrics ++ [{Name, filter_history_entries(History)}]);
filter_metrics([{Name, Metrics}|Rest], FilteredMetrics) ->
  filter_metrics(Rest, FilteredMetrics ++ [{Name, Metrics}]).

filter_history_entries(HistoryEntries) ->
  filter_history_entries(HistoryEntries, []).
filter_history_entries([], FilteredHistoryEntries) ->
  FilteredHistoryEntries;
filter_history_entries([{Timestamp, Values}|Rest], FilteredHistoryEntries) ->
  filter_history_entries(Rest, FilteredHistoryEntries ++ [filter_history_entry(Timestamp, Values)]).

filter_history_entry(Timestamp, Values) ->
  [{<<"timestamp">>, Timestamp}, {<<"values">>, lists:map(fun({event, Value}) -> Value end, Values)}].

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

vm() ->
  [
    {<<"memory">>, folsom_vm_metrics:get_memory()}
  ].

filtered_vm() ->
  vm().

ets() ->
  [
    {<<"ets">>, ets_metrics()}
  ].

filtered_ets() ->
  lists:map(
    fun(TableData) ->
        {
          proplists:get_value(name, TableData),
          [
            {compressed, proplists:get_value(compressed, TableData)},
            {size, proplists:get_value(size, TableData)},
            {type, atom_to_binary(proplists:get_value(type, TableData), latin1)},
            {protection, atom_to_binary(proplists:get_value(protection, TableData), latin1)}
          ]
        }
  end, ets_metrics()).

ets_metrics() ->
  lists:map(fun(Name) -> ets:info(Name) end, ets:all()).

keys_to_strings(Pairs) ->
  lists:map(
    fun({K, V}) ->
        {list_to_binary(lists:flatten(io_lib:format("~p", [K]))), V}
    end, Pairs).

process_metrics() ->
  lists:map(
    fun(ProcessName) ->
        Pid = whereis(ProcessName),
        {
          ProcessName,
          [
            process_info(Pid, memory),
            process_info(Pid, heap_size),
            process_info(Pid, stack_size),
            process_info(Pid, message_queue_len)
          ]
        }
    end, registered()).

filtered_process_metrics() ->
  process_metrics().

%% Gen server
start_link() ->
  gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

init([]) ->
  lager:debug("Starting ~p", [?MODULE]),

  Dispatch = cowboy_router:compile(
    [
      {'_', 
        [
          {"/", erldns_metrics_root_handler, []}
        ]
      }
    ]
  ),

  {ok, _} = cowboy:start_http(?MODULE, 10, [{port, port()}], [{env, [{dispatch, Dispatch}]}]),

  {ok, #state{}}.

handle_call(_Message, _From, State) ->
  {reply, ok, State}.
handle_cast(_, State) ->
  {noreply, State}.
handle_info(_, State) ->
  {noreply, State}.
terminate(_, _) ->
  ok.
code_change(_PreviousVersion, State, _Extra) ->
  {ok, State}.

port() ->
 proplists:get_value(port, metrics_env(), ?DEFAULT_PORT).

metrics_env() ->
  case application:get_env(erldns, metrics) of
    {ok, MetricsEnv} -> MetricsEnv;
    _ -> []
  end.
