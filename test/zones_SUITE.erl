-module(zones_SUITE).
-compile([export_all, nowarn_export_all]).

-behaviour(ct_suite).

-include_lib("stdlib/include/assert.hrl").

-spec all() -> [ct_suite:ct_test_def()].
all() ->
    [
        {group, loader}
    ].

-spec groups() -> [ct_suite:ct_group_def()].
groups() ->
    [
        {loader, [], [
            defaults,
            bad_config,
            strict_true,
            strict_false,
            strict_passes,
            bad_json,
            bad_json_not_list,
            wildcard_loose,
            valid_zones
        ]}
    ].

-spec init_per_suite(ct_suite:ct_config()) -> ct_suite:ct_config().
init_per_suite(Config) ->
    Config.

-spec end_per_suite(ct_suite:ct_config()) -> term().
end_per_suite(_) ->
    application:unset_env(erldns, zones).

-spec init_per_group(ct_suite:ct_groupname(), ct_suite:ct_config()) -> ct_suite:ct_config().
init_per_group(loader, Config) ->
    meck:new(erldns_zone_parser, [passthrough, no_link]),
    meck:expect(erldns_zone_parser, zone_to_erlang, fun(Term) -> Term end),
    meck:new(erldns_zone_cache, [passthrough, no_link]),
    meck:expect(erldns_zone_cache, put_zone, fun
        (false) -> {error, false};
        (Term) -> Term
    end),
    Config.

-spec end_per_group(ct_suite:ct_groupname(), ct_suite:ct_config()) -> term().
end_per_group(loader, _Config) ->
    meck:unload().

-spec init_per_testcase(ct_suite:ct_testcase(), ct_suite:ct_config()) -> ct_suite:ct_config().
init_per_testcase(_, Config) ->
    Config.

-spec end_per_testcase(ct_suite:ct_testcase(), ct_suite:ct_config()) -> term().
end_per_testcase(_, Config) ->
    Config.

%% Tests
defaults(_) ->
    ?assertError(enoent, erldns_zone_loader:load_zones()).

bad_config(_) ->
    application:set_env(erldns, zones, #{strict => very_invalid}),
    ?assertError({badconfig, _}, erldns_zone_loader:load_zones()).

strict_true(_) ->
    application:set_env(erldns, zones, #{strict => true}),
    ?assertError(enoent, erldns_zone_loader:load_zones()).

strict_false(_) ->
    application:set_env(erldns, zones, #{strict => false}),
    ?assertMatch({ok, 0}, erldns_zone_loader:load_zones()).

strict_passes(Config) ->
    DataDir = proplists:get_value(data_dir, Config),
    Path = filename:join(DataDir, "good.json"),
    application:set_env(erldns, zones, #{path => Path}),
    ?assertMatch({ok, 0}, erldns_zone_loader:load_zones()).

bad_json(Config) ->
    DataDir = proplists:get_value(data_dir, Config),
    Path = filename:join(DataDir, "bad_json.json"),
    application:set_env(erldns, zones, #{path => Path}),
    ?assertError({invalid_byte, _}, erldns_zone_loader:load_zones()).

bad_json_not_list(Config) ->
    DataDir = proplists:get_value(data_dir, Config),
    Path = filename:join(DataDir, "json_not_list.json"),
    application:set_env(erldns, zones, #{path => Path}),
    ?assertError(invalid_zone_file, erldns_zone_loader:load_zones()).

wildcard_loose(Config) ->
    DataDir = proplists:get_value(data_dir, Config),
    application:set_env(erldns, zones, #{strict => false, path => DataDir}),
    ?assertMatch({ok, 1}, erldns_zone_loader:load_zones()).

valid_zones(Config) ->
    DataDir = proplists:get_value(data_dir, Config),
    Path = filename:join(DataDir, "standard.json"),
    application:set_env(erldns, zones, #{path => Path}),
    ?assertMatch({ok, 1}, erldns_zone_loader:load_zones()).
