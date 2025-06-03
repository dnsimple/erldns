-module(erldns_zone_loader).
-moduledoc """
Functions for loading zones from local or remote sources.

## Configuration
```erlang
{erldns, [
    {zones, #{
        path => "zones.json",
        strict => true
    }
]}
```
See the type `t:config/0` for details.
""".

-include_lib("kernel/include/logger.hrl").

-doc """
Zone loader configuration.

Path can be a wildcard, and `strict` declares whether load failure should crash or be ignored.
""".
-type config() :: #{
    path => file:name(),
    strict => boolean()
}.

-export([load_zones/0, load_zones/1]).

-define(PATH, "zones.json").

-doc "Load zones.".
-spec load_zones() -> {ok, integer()}.
load_zones() ->
    Config = get_config(),
    load_zones(Config).

-doc """
Load zones from a file in strict or loose mode.
""".
-spec load_zones(config()) -> {ok, integer()}.
load_zones(#{path := Path, strict := Strictness}) ->
    load_zones(Strictness, Path).

-spec load_zones(boolean(), file:name()) -> {ok, integer()}.
load_zones(Strictness, Path) when is_boolean(Strictness), is_list(Path) ->
    case filelib:is_dir(Path) of
        true ->
            ZoneFiles = filelib:wildcard(filename:join([Path, "*.json"])),
            load_zone_files(Strictness, ZoneFiles, length(ZoneFiles));
        false ->
            load_zone_files(Strictness, [Path], 1)
    end.

-spec load_zone_files(boolean(), [file:name()], non_neg_integer()) -> {ok, integer()}.
load_zone_files(Strictness, ZoneFileNames, ZoneFilesCount) ->
    {_, Result} = lists:foldl(
        fun(Filename, {FileNumber, ZoneCount}) ->
            Progress = io_lib:format("~p/~p", [FileNumber, ZoneFilesCount]),
            ?LOG_INFO(#{what => loading_zone_file, progress => Progress}),
            case {Strictness, load_zone_file(Filename)} of
                {true, {error, Reason}} -> erlang:error(Reason);
                {_, {ok, N}} -> {FileNumber + 1, ZoneCount + N};
                {_, {error, _}} -> {FileNumber + 1, ZoneCount}
            end
        end,
        {1, 0},
        ZoneFileNames
    ),
    {ok, Result}.

-spec load_zone_file(file:name()) -> {ok, integer()} | {error, term()}.
load_zone_file(Filename) ->
    maybe
        ?LOG_INFO(#{what => parsing_zone_file}),
        {ok, FileContent} ?= file:read_file(Filename),
        {ok, JsonZones} ?= safe_json_decode(FileContent),
        ?LOG_INFO(#{what => putting_zones_into_cache}),
        true ?= lists:all(fun load_zone/1, JsonZones),
        Count = length(JsonZones),
        ?LOG_INFO(#{what => loaded_zones, count => Count}),
        {ok, Count}
    else
        false ->
            ?LOG_ERROR(#{what => read_zone_error, reason => failed_to_load_zone}),
            {error, failed_to_load_zone};
        {error, Reason} ->
            ?LOG_ERROR(#{what => read_zone_error, reason => Reason}),
            {error, Reason}
    end.

load_zone(JsonZone) ->
    Zone = erldns_zone_parser:zone_to_erlang(JsonZone),
    case erldns_zone_cache:put_zone(Zone) of
        {error, Reason} ->
            ?LOG_ERROR(#{what => put_zone_error, reason => Reason, json => JsonZone}),
            false;
        _ ->
            true
    end.

% Internal API
get_config() ->
    case application:get_env(erldns, zones, default_config()) of
        #{path := Path, strict := Strictness} = Config when
            is_list(Path), is_boolean(Strictness)
        ->
            Config;
        #{strict := Strictness} = Config when
            is_boolean(Strictness)
        ->
            Config#{path => ?PATH};
        #{path := Path} = Config when
            is_list(Path)
        ->
            Config#{strict => true};
        Other ->
            erlang:error({badconfig, Other})
    end.

-spec default_config() -> config().
default_config() ->
    #{path => ?PATH, strict => true}.

safe_json_decode(Binary) ->
    try json:decode(Binary) of
        List when is_list(List) ->
            {ok, List};
        _ ->
            {error, invalid_zone_file}
    catch
        error:Reason -> {error, Reason}
    end.
