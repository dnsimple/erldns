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
See the type `t:erldns_zones:config/0` for details.
""".

-export([get_config/0, get_config/1]).
-export([load_zones/0, load_zones/1]).

-doc "Load zones.".
-spec load_zones() -> non_neg_integer().
load_zones() ->
    load_zones(#{}).

-doc "Load zones from a given configuration, see `t:erldns_zones:config/0` for details.".
-spec load_zones(erldns_zones:config() | file:name()) -> non_neg_integer().
load_zones(ConfigOrPath) ->
    Config = get_config(ConfigOrPath),
    case erldns_zone_loader_getter:load_zones(Config) of
        {error, Error} ->
            erlang:error(Error);
        Count ->
            Count
    end.

% Internal API
-spec get_config() -> erldns_zones:config().
get_config() ->
    Config = application:get_env(erldns, zones, #{}),
    get_config(Config).

-spec get_config(map() | file:name()) -> erldns_zones:config().
get_config(Path) when is_list(Path) ->
    get_config(#{path => Path});
get_config(Config) when is_map(Config) ->
    Format = maps:get(format, Config, json),
    Timeout = maps:get(timeout, Config, timer:minutes(30)),
    Path = maps:get(path, Config, undefined),
    Strict = maps:get(strict, Config, undefined =/= Path),
    assert_valid_format(Format),
    assert_valid_timeout(Timeout),
    assert_valid_path(Path, Strict),
    case Path of
        undefined ->
            #{};
        _ ->
            #{path => Path, strict => Strict, format => Format, timeout => Timeout}
    end.

-spec assert_valid_format(erldns_zones:format()) -> ok | no_return().
assert_valid_format(Format) ->
    case Format =:= json orelse Format =:= zonefile orelse Format =:= auto of
        true ->
            ok;
        false ->
            erlang:error({badconfig, invalid_format_value})
    end.

-spec assert_valid_timeout(timeout()) -> ok | no_return().
assert_valid_timeout(Timeout) ->
    case (is_integer(Timeout) andalso Timeout > 0) orelse infinity =:= Timeout of
        true ->
            ok;
        false ->
            erlang:error({badconfig, invalid_timeout_value})
    end.

-spec assert_valid_path(file:name() | undefined, boolean()) -> ok | no_return().
assert_valid_path(_, Strict) when not is_boolean(Strict) ->
    erlang:error({badconfig, invalid_strict_value});
assert_valid_path(Path, Strict) when is_list(Path) ->
    fail_if_strict_and_path_not_found(Path, Strict);
assert_valid_path(_, true) ->
    erlang:error({badconfig, enoent});
assert_valid_path(undefined, _) ->
    undefined;
assert_valid_path(_, _) ->
    undefined.

-spec fail_if_strict_and_path_not_found(file:name(), boolean()) -> ok | no_return().
fail_if_strict_and_path_not_found(Path, Strict) ->
    case not Strict orelse filelib:is_dir(Path) orelse filelib:is_file(Path) of
        true ->
            ok;
        false ->
            erlang:error({badconfig, enoent})
    end.
