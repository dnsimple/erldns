%% Copyright (c) DNSimple Corporation
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
%% ACTION OF T, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
%% OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

%% @doc gen server that provides access to metrics recorded through Folsom.
-module(erldns_metrics).

-export([maybe_start/0]).

-export([
    metrics/0,
    stats/0,
    vm/0,
    ets/0,
    process_metrics/0,
    filtered_metrics/0,
    filtered_stats/0,
    filtered_vm/0,
    filtered_ets/0,
    filtered_process_metrics/0
]).

-define(DEFAULT_PORT, 8082).

-include_lib("kernel/include/logger.hrl").

-doc """
Configuration parameters, see the module documentation for details.
""".
-type config() :: #{
    port := 0..65535
}.

-type env() :: [{atom(), term()}].

-spec maybe_start() -> ok | {ok, pid()} | {error, any()}.
maybe_start() ->
    case ensure_valid_config() of
        disabled ->
            ok;
        false ->
            error(bad_configuration);
        Config ->
            start(Config)
    end.

-spec start(config()) -> {ok, pid()} | {error, any()}.
start(#{port := Port}) ->
    Dispatch = cowboy_router:compile(
        [
            {'_', [
                {"/", erldns_metrics_root_handler, []}
            ]}
        ]
    ),
    TransportOpts = #{socket_opts => [inet, inet6, {ip, any}, {port, Port}]},
    ProtocolOpts = #{env => #{dispatch => Dispatch}},
    cowboy:start_clear(?MODULE, TransportOpts, ProtocolOpts).

metrics() ->
    lists:map(
        fun(Name) ->
            {Name, folsom_metrics:get_metric_value(Name)}
        end,
        folsom_metrics:get_metrics()
    ).

filtered_metrics() ->
    filter_metrics(metrics()).

stats() ->
    Histograms = [udp_handoff_histogram, tcp_handoff_histogram, request_handled_histogram],
    lists:map(
        fun(Name) ->
            {Name, folsom_metrics:get_histogram_statistics(Name)}
        end,
        Histograms
    ).

filtered_stats() ->
    filter_stats(stats()).

% Functions to clean up metrics so they can be returned as JSON.
filter_metrics(Metrics) ->
    filter_metrics(Metrics, []).

filter_metrics([], FilteredMetrics) ->
    FilteredMetrics;
filter_metrics([{Name, History = [{Timestamp, _Values} | _Rest]} | Rest], FilteredMetrics) when is_number(Timestamp) ->
    filter_metrics(Rest, FilteredMetrics ++ [{Name, filter_history_entries(History)}]);
filter_metrics([{Name, Metrics} | Rest], FilteredMetrics) ->
    filter_metrics(Rest, FilteredMetrics ++ [{Name, Metrics}]).

filter_history_entries(HistoryEntries) ->
    filter_history_entries(HistoryEntries, []).
filter_history_entries([], FilteredHistoryEntries) ->
    FilteredHistoryEntries;
filter_history_entries([{Timestamp, Values} | Rest], FilteredHistoryEntries) ->
    filter_history_entries(Rest, FilteredHistoryEntries ++ [filter_history_entry(Timestamp, Values)]).

filter_history_entry(Timestamp, Values) ->
    [{<<"timestamp">>, Timestamp}, {<<"values">>, lists:map(fun({event, Value}) -> Value end, Values)}].

% Functions to clean up the stats so they can be returned as JSON.
filter_stats(Stats) ->
    filter_stats(Stats, []).

filter_stats([], FilteredStats) ->
    FilteredStats;
filter_stats([{Name, Stats} | Rest], FilteredStats) ->
    filter_stats(Rest, FilteredStats ++ [{Name, filter_stat_set(Stats)}]).

filter_stat_set(Stats) ->
    filter_stat_set(Stats, []).

filter_stat_set([], FilteredStatSet) ->
    FilteredStatSet;
filter_stat_set([{percentile, Percentiles} | Rest], FilteredStatSet) ->
    filter_stat_set(Rest, FilteredStatSet ++ [{percentile, keys_to_strings(Percentiles)}]);
filter_stat_set([{histogram, _} | Rest], FilteredStatSet) ->
    filter_stat_set(Rest, FilteredStatSet);
filter_stat_set([Pair | Rest], FilteredStatSet) ->
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
        end,
        ets_metrics()
    ).

ets_metrics() ->
    lists:map(fun(Name) -> ets:info(Name) end, ets:all()).

keys_to_strings(Pairs) ->
    lists:map(
        fun({K, V}) ->
            {list_to_binary(lists:flatten(io_lib:format("~p", [K]))), V}
        end,
        Pairs
    ).

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
        end,
        registered()
    ).

filtered_process_metrics() ->
    process_metrics().

-spec ensure_valid_config() -> false | disabled | config().
ensure_valid_config() ->
    maybe
        {true, Env} ?= env(),
        {true, Port} ?= port(Env),
        #{port => Port}
    end.

-spec port(env()) -> {true, 1..65535} | false.
port(Env) ->
    case proplists:get_value(port, Env, ?DEFAULT_PORT) of
        Port when is_integer(Port), 0 < Port, Port =< 65535 ->
            {true, Port};
        OtherPort ->
            ?LOG_ERROR(#{what => erldns_admin_bad_config, port => OtherPort}),
            false
    end.

-spec env() -> {true, env()} | false | disabled.
env() ->
    case application:get_env(erldns, metrics) of
        {ok, Env} when is_list(Env) -> {true, Env};
        {ok, _} -> false;
        _ -> disabled
    end.
