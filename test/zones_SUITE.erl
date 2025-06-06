-module(zones_SUITE).
-compile([export_all, nowarn_export_all]).

-behaviour(ct_suite).

-include_lib("stdlib/include/assert.hrl").
-include_lib("dns_erlang/include/dns.hrl").
-include_lib("erldns/include/erldns.hrl").

-spec all() -> [ct_suite:ct_test_def()].
all() ->
    [
        {group, loader},
        {group, codec},
        {group, cache}
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
            valid_zones,
            load_dnssec_zone,
            wildcard_loose
        ]},
        {codec, [], [
            encode_meta_to_json,
            custom_decode
        ]},
        {cache, [], [
            put_zone_rrset_records_count_with_existing_rrset_test,
            put_zone_rrset_records_count_with_new_rrset_test,
            put_zone_rrset_records_count_matches_cache_test,
            put_zone_rrset_records_count_with_dnssec_zone_and_new_rrset_test,
            delete_zone_rrset_records_count_width_existing_rrset_test,
            delete_zone_rrset_records_count_width_dnssec_zone_and_existing_rrset_test,
            delete_zone_rrset_records_count_matches_cache_test
        ]}
    ].

-spec init_per_suite(ct_suite:ct_config()) -> ct_suite:ct_config().
init_per_suite(Config) ->
    application:unset_env(erldns, zones),
    Config.

-spec end_per_suite(ct_suite:ct_config()) -> term().
end_per_suite(_) ->
    application:unset_env(erldns, zones).

-spec init_per_group(ct_suite:ct_groupname(), ct_suite:ct_config()) -> ct_suite:ct_config().
init_per_group(cache, Config) ->
    meck:new(telemetry, [passthrough, no_link]),
    Config;
init_per_group(codec, Config) ->
    Config;
init_per_group(loader, Config) ->
    meck:new(erldns_zone_codec, [passthrough, no_link]),
    meck:expect(erldns_zone_codec, decode, fun(Term) -> Term end),
    meck:new(erldns_zone_cache, [passthrough, no_link]),
    meck:expect(erldns_zone_cache, put_zone, fun
        (false) -> {error, false};
        (Term) -> Term
    end),
    Config.

-spec end_per_group(ct_suite:ct_groupname(), ct_suite:ct_config()) -> term().
end_per_group(codec, _Config) ->
    ok;
end_per_group(cache, _Config) ->
    ?assert(meck:validate(telemetry)),
    meck:unload();
end_per_group(loader, _Config) ->
    meck:unload().

-spec init_per_testcase(ct_suite:ct_testcase(), ct_suite:ct_config()) -> ct_suite:ct_config().
init_per_testcase(_, Config) ->
    Config.

-spec end_per_testcase(ct_suite:ct_testcase(), ct_suite:ct_config()) -> term().
end_per_testcase(_, Config) ->
    Config.

%% Tests
encode_meta_to_json(_) ->
    {ok, _} = erldns_zone_cache:start_link(),
    {ok, _} = erldns_zone_codec:start_link(),
    Z = #zone{
        name = ~"example.com",
        authority = [#dns_rr{name = ~"example.com", type = ?DNS_TYPE_SOA}]
    },
    Data = erldns_zone_codec:encode(Z, #{mode => zone_meta_to_json}),
    JSON = iolist_to_binary(json:encode(Data)),
    ?assert(is_binary(JSON)),
    ?assertMatch(
        #{
            ~"erldns" := #{
                ~"zone" := #{
                    ~"name" := ~"example.com",
                    ~"version" := _,
                    ~"records_count" := 0
                }
            }
        },
        json:decode(JSON)
    ).

custom_decode(_) ->
    Record = sample_custom_zone_codec:decode(#{
        ~"name" => ~"example.com",
        ~"type" => ~"SAMPLE",
        ~"ttl" => 60,
        ~"data" => #{~"dname" => ~"example.net"},
        ~"context" => null
    }),
    ?assertEqual(~"example.com", Record#dns_rr.name),
    ?assertEqual(40000, Record#dns_rr.type),
    ?assertEqual(60, Record#dns_rr.ttl),
    ?assertEqual(~"example.net", Record#dns_rr.data),
    ?assertEqual(not_implemented, sample_custom_zone_codec:decode(#{})).

defaults(_) ->
    ?assertEqual(0, erldns_zone_loader:load_zones()).

bad_config(_) ->
    application:set_env(erldns, zones, #{strict => very_invalid}),
    ?assertError({badconfig, _}, erldns_zone_loader:load_zones()).

strict_true(_) ->
    application:set_env(erldns, zones, #{strict => true}),
    ?assertError({badconfig, enoent}, erldns_zone_loader:load_zones()).

strict_false(_) ->
    application:set_env(erldns, zones, #{strict => false}),
    ?assertMatch(0, erldns_zone_loader:load_zones()).

strict_passes(Config) ->
    DataDir = proplists:get_value(data_dir, Config),
    Path = filename:join(DataDir, "good.json"),
    application:set_env(erldns, zones, #{path => Path}),
    ?assertMatch(0, erldns_zone_loader:load_zones()).

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

valid_zones(Config) ->
    DataDir = proplists:get_value(data_dir, Config),
    Path = filename:join(DataDir, "standard.json"),
    application:set_env(erldns, zones, #{path => Path}),
    ?assertMatch(1, erldns_zone_loader:load_zones()).

load_dnssec_zone(Config) ->
    DataDir = proplists:get_value(data_dir, Config),
    Path = filename:join(DataDir, "dnssec-zone.json"),
    application:set_env(erldns, zones, #{path => Path, strict => true}),
    ?assertMatch(1, erldns_zone_loader:load_zones()).

wildcard_loose(Config) ->
    DataDir = proplists:get_value(data_dir, Config),
    application:set_env(erldns, zones, #{strict => false, path => DataDir}),
    ?assertMatch(3, erldns_zone_loader:load_zones()).

put_zone_rrset_records_count_with_existing_rrset_test(Config) ->
    setup_test(Config, ?FUNCTION_NAME),
    ZoneName = ~"example.com",
    ZoneBase = erldns_zone_cache:find_zone(dns:dname_to_lower(ZoneName)),
    erldns_zone_cache:put_zone_rrset(
        {ZoneName, ~"irrelevantDigest",
            [
                #dns_rr{
                    data = #dns_rrdata_cname{dname = ~"google.com"},
                    name = ~"cname.example.com",
                    ttl = 5,
                    type = 5
                }
            ],
            []},
        ~"cname.example.com",
        5,
        1
    ),
    ZoneModified = erldns_zone_cache:find_zone(dns:dname_to_lower(ZoneName)),
    % There should be no change in record count
    ?assertEqual(ZoneBase#zone.record_count, ZoneModified#zone.record_count).

put_zone_rrset_records_count_with_new_rrset_test(Config) ->
    setup_test(Config, ?FUNCTION_NAME),
    ZoneName = ~"example.com",
    ZoneBase = erldns_zone_cache:find_zone(dns:dname_to_lower(ZoneName)),
    erldns_zone_cache:put_zone_rrset(
        {ZoneName, ~"irrelevantDigest",
            [
                #dns_rr{
                    data = #dns_rrdata_a{ip = ~"5,5,5,5"},
                    name = ~"a2.example.com",
                    ttl = 5,
                    type = 1
                }
            ],
            []},
        ~"a2.example.com",
        5,
        1
    ),
    ZoneModified = erldns_zone_cache:find_zone(dns:dname_to_lower(ZoneName)),
    % New RRSet is being added with one record we should see an increase by 1
    ?assertEqual(ZoneBase#zone.record_count + 1, ZoneModified#zone.record_count).

put_zone_rrset_records_count_matches_cache_test(Config) ->
    setup_test(Config, ?FUNCTION_NAME),
    ZoneName = ~"example.com",
    erldns_zone_cache:put_zone_rrset(
        {ZoneName, ~"irrelevantDigest",
            [
                #dns_rr{
                    data = #dns_rrdata_a{ip = ~"5,5,5,5"},
                    name = ~"a2.example.com",
                    ttl = 5,
                    type = 1
                }
            ],
            []},
        ~"a2.example.com",
        5,
        1
    ),
    ZoneModified = erldns_zone_cache:find_zone(dns:dname_to_lower(ZoneName)),
    % New RRSet is being added with one record we should see an increase by 1
    ?assertEqual(
        length(erldns_zone_cache:get_zone_records(ZoneName)), ZoneModified#zone.record_count
    ).

put_zone_rrset_records_count_with_dnssec_zone_and_new_rrset_test(Config) ->
    setup_test(Config, ?FUNCTION_NAME),
    ZoneName = ~"example-dnssec.com",
    Zone = erldns_zone_cache:find_zone(dns:dname_to_lower(ZoneName)),
    erldns_zone_cache:put_zone_rrset(
        {ZoneName, ~"irrelevantDigest",
            [
                #dns_rr{
                    data = #dns_rrdata_cname{dname = ~"google.com"},
                    name = ~"cname.example-dnssec.com",
                    ttl = 60,
                    type = 5
                }
            ],
            []},
        ~"cname.example-dnssec.com",
        5,
        1
    ),
    ZoneModified = erldns_zone_cache:find_zone(dns:dname_to_lower(ZoneName)),
    % New RRSet entry for the CNAME + 1 RRSig record
    ?assertEqual(Zone#zone.record_count + 2, ZoneModified#zone.record_count).

delete_zone_rrset_records_count_width_existing_rrset_test(Config) ->
    setup_test(Config, ?FUNCTION_NAME),
    ZoneName = ~"example.com",
    ZoneBase = erldns_zone_cache:find_zone(dns:dname_to_lower(ZoneName)),
    erldns_zone_cache:delete_zone_rrset(
        ZoneName,
        ~"irrelevantDigest",
        dns:dname_to_lower(~"cname.example.com"),
        5,
        1
    ),
    ZoneModified = erldns_zone_cache:find_zone(dns:dname_to_lower(ZoneName)),
    % Deletes a CNAME RRSet with one record
    ?assertEqual(ZoneBase#zone.record_count - 1, ZoneModified#zone.record_count).

delete_zone_rrset_records_count_width_dnssec_zone_and_existing_rrset_test(Config) ->
    setup_test(Config, ?FUNCTION_NAME),
    ZoneName = ~"example-dnssec.com",
    ZoneBase = erldns_zone_cache:find_zone(dns:dname_to_lower(ZoneName)),
    erldns_zone_cache:delete_zone_rrset(
        ZoneName,
        ~"irrelevantDigest",
        dns:dname_to_lower(~"cname2.example-dnssec.com"),
        5,
        2
    ),
    ZoneModified = erldns_zone_cache:find_zone(dns:dname_to_lower(ZoneName)),
    % Deletes a CNAME RRSet with one record + RRSig
    ?assertEqual(ZoneBase#zone.record_count - 2, ZoneModified#zone.record_count).

delete_zone_rrset_records_count_matches_cache_test(Config) ->
    setup_test(Config, ?FUNCTION_NAME),
    ZoneName = ~"example-dnssec.com",
    erldns_zone_cache:delete_zone_rrset(
        ZoneName,
        ~"irrelevantDigest",
        dns:dname_to_lower(~"cname2.example-dnssec.com"),
        5,
        2
    ),
    ZoneModified = erldns_zone_cache:find_zone(dns:dname_to_lower(ZoneName)),
    % Deletes a CNAME RRSet with one record + RRSig
    ?assertEqual(
        length(erldns_zone_cache:get_zone_records(ZoneName)), ZoneModified#zone.record_count
    ).

setup_test(Config, _) ->
    {ok, _} = erldns_zone_codec:start_link(),
    {ok, _} = erldns_zone_cache:start_link(),
    DataDir = proplists:get_value(data_dir, Config),
    application:set_env(erldns, zones, #{path => filename:join(DataDir, "standard.json")}),
    ?assertMatch(1, erldns_zone_loader:load_zones()),
    application:set_env(erldns, zones, #{path => filename:join(DataDir, "dnssec-zone.json")}),
    ?assertMatch(1, erldns_zone_loader:load_zones()).
