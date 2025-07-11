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
            loader_coverage,
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
            bad_custom_codecs_module_does_not_exist,
            bad_custom_codecs_module_does_not_export_callbacks,
            custom_decode,
            encode_meta_to_json,
            encode_meta_to_json_dnssec,
            json_to_erlang,
            json_to_erlang_txt_spf_records,
            json_to_erlang_ensure_sorting_and_defaults,
            json_record_to_erlang,
            json_record_soa_to_erlang,
            json_record_ns_to_erlang,
            json_record_a_to_erlang,
            json_record_aaaa_to_erlang,
            json_record_cds_to_erlang,
            parse_json_keys_unsorted_proplists_time_unit,
            parse_json_keys_unsorted_proplists
        ]},
        {cache, [], [
            cache_coverage,
            lookup_zone,
            get_zone_records,
            get_records_by_name,
            get_records_by_name_and_type,
            get_records_by_name_ent,
            get_records_by_name_wildcard,
            get_records_by_name_wildcard_strict,
            get_authoritative_zone,
            get_delegations,
            is_in_any_zone,
            is_name_in_zone,
            is_record_name_in_zone,
            is_record_name_in_zone_strict,
            put_zone,
            put_zone_rrset,
            put_zone_rrset_records_count_with_existing_rrset,
            put_zone_rrset_records_count_with_new_rrset,
            put_zone_rrset_records_count_matches_cache,
            put_zone_rrset_records_count_with_dnssec_zone_and_new_rrset,
            delete_zone_rrset_records_count_width_existing_rrset,
            delete_zone_rrset_records_count_width_dnssec_zone_and_existing_rrset,
            delete_zone_rrset_records_count_matches_cache,
            delete_zone_rrset_records_count_underflow,
            delete_zone_rrset_records_zone_not_found
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
init_per_group(loader, Config) ->
    meck:new(erldns_zone_codec, [passthrough, no_link]),
    meck:expect(erldns_zone_codec, decode, fun(Term) -> Term end),
    meck:new(erldns_zone_cache, [passthrough, no_link]),
    meck:expect(erldns_zone_cache, put_zone, fun
        (false) -> {error, false};
        (Term) -> Term
    end),
    Config;
init_per_group(cache, Config) ->
    Fun = fun() ->
        setup_test(Config, cache),
        receive
            stop -> ok
        end
    end,
    Pid = spawn(Fun),
    [{cache, Pid} | Config];
init_per_group(_, Config) ->
    Config.

-spec end_per_group(ct_suite:ct_groupname(), ct_suite:ct_config()) -> term().
end_per_group(cache, Config) ->
    Pid = proplists:get_value(cache, Config),
    ct:pal("Cache process is alive: ~p~n", [erlang:is_process_alive(Pid)]),
    exit(Pid, stop);
end_per_group(loader, _Config) ->
    meck:unload();
end_per_group(_, _Config) ->
    ok.

-spec init_per_testcase(ct_suite:ct_testcase(), ct_suite:ct_config()) -> ct_suite:ct_config().
init_per_testcase(_, Config) ->
    Config.

-spec end_per_testcase(ct_suite:ct_testcase(), ct_suite:ct_config()) -> term().
end_per_testcase(_, _) ->
    application:unset_env(erldns, zones).

%% Tests
bad_custom_codecs_module_does_not_exist(_) ->
    erlang:process_flag(trap_exit, true),
    application:set_env(erldns, zones, #{codecs => [this_module_does_not_exist]}),
    ?assertMatch({error, {{badcodec, {module, _}}, _}}, erldns_zone_codec:start_link()).

bad_custom_codecs_module_does_not_export_callbacks(_) ->
    erlang:process_flag(trap_exit, true),
    application:set_env(erldns, zones, #{codecs => [?MODULE]}),
    ?assertMatch(
        {error, {{badcodec, {module_does_not_export_call, ?MODULE}}, _}},
        erldns_zone_codec:start_link()
    ).

custom_decode(_) ->
    application:set_env(erldns, zones, #{codecs => [sample_custom_zone_codec]}),
    {ok, _} = erldns_zone_codec:start_link(),
    Input = #{
        ~"name" => ~"example.com",
        ~"records" => [
            #{
                ~"name" => ~"example.com",
                ~"type" => ~"SAMPLE",
                ~"ttl" => 60,
                ~"data" => #{~"dname" => ~"example.net"},
                ~"context" => null
            }
        ]
    },
    Zone = erldns_zone_codec:decode(Input),
    ?assertMatch(#zone{records = [_]}, Zone),
    #zone{records = [Record]} = Zone,
    ?assertEqual(~"example.com", Record#dns_rr.name),
    ?assertEqual(40000, Record#dns_rr.type),
    ?assertEqual(60, Record#dns_rr.ttl),
    ?assertEqual(~"example.net", Record#dns_rr.data),
    ?assertEqual(not_implemented, sample_custom_zone_codec:decode(#{})).

encode_meta_to_json(_) ->
    {ok, _} = erldns_zone_cache:start_link(),
    {ok, _} = erldns_zone_codec:start_link(),
    ZoneName = dns:dname_to_lower(~"example.com"),
    Z = erldns_zone_codec:build_zone(ZoneName, ~"", [], []),
    erldns_zone_cache:put_zone(Z),
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

encode_meta_to_json_dnssec(Config) ->
    DataDir = proplists:get_value(data_dir, Config),
    Path = filename:join(DataDir, "dnssec-zone.json"),
    application:set_env(erldns, zones, #{
        path => Path,
        codecs => [sample_custom_zone_codec]
    }),
    {ok, _} = erldns_zone_cache:start_link(),
    {ok, _} = erldns_zone_codec:start_link(),
    {ok, _} = erldns_zone_loader:start_link(),
    ZoneName = ~"example-dnssec.com",
    RecordName = ~"example-dnssec.com",
    Z = erldns_zone_codec:build_zone(ZoneName, ~"", [], []),
    Data = erldns_zone_codec:encode(Z, #{mode => {zone_records_to_json, RecordName}}),
    JSON = iolist_to_binary(json:encode(Data)),
    ?assert(is_binary(JSON)),
    ?assertMatch(L when 8 =:= length(L), json:decode(JSON)).

json_to_erlang(_) ->
    R = erldns_zone_parser:decode(json:decode(input()), []),
    ?assertMatch(#zone{}, R).

json_to_erlang_txt_spf_records(_) ->
    I = ~"""
    {
      "name": "example.com",
      "records": [
        {
          "context": [],
          "data": {
            "txts": ["this is a test"]
          },
          "name": "example.com",
          "ttl": 3600,
          "type": "TXT"
        },
        {
          "context": [],
          "data": {
            "txts": ["v=spf1 a mx ~all"]
          },
          "name": "example.com",
          "ttl": 3600,
          "type": "SPF"
        }
      ],
      "sha": "10ea56ad7be9d3e6e75be3a15ef0dfabe9facafba486d74914e7baf8fb36638e"
    }
    """,
    Json = json:decode(I),
    R = erldns_zone_parser:decode(Json, []),
    Expected = [
        #dns_rr{
            name = ~"example.com",
            type = 16,
            class = 1,
            ttl = 3600,
            data = #dns_rrdata_txt{txt = [~"this is a test"]}
        },
        #dns_rr{
            name = ~"example.com",
            type = 99,
            class = 1,
            ttl = 3600,
            data = #dns_rrdata_spf{spf = [~"v=spf1 a mx ~all"]}
        }
    ],
    ?assertMatch(
        #zone{
            name = ~"example.com",
            version = Sha,
            records = Expected,
            keysets = []
        } when is_binary(Sha),
        R
    ).

json_to_erlang_ensure_sorting_and_defaults(_) ->
    ?assertMatch(
        #zone{name = ~"foo.org", version = <<>>, records = [], keysets = []},
        erldns_zone_parser:decode(#{~"name" => ~"foo.org", ~"records" => []}, [])
    ).

json_record_to_erlang(_) ->
    ?assertEqual(not_implemented, erldns_zone_parser:json_record_to_erlang(#{})),
    Name = ~"example.com",
    Data = #{
        ~"name" => Name, ~"type" => ~"SOA", ~"ttl" => 3600, ~"data" => null, ~"context" => null
    },
    ?assertEqual(not_implemented, erldns_zone_parser:json_record_to_erlang(Data)).

json_record_soa_to_erlang(_) ->
    Name = ~"example.com",
    ?assertEqual(
        #dns_rr{
            name = Name,
            type = ?DNS_TYPE_SOA,
            data =
                #dns_rrdata_soa{
                    mname = ~"ns1.example.com",
                    rname = ~"admin.example.com",
                    serial = 12345,
                    refresh = 555,
                    retry = 666,
                    expire = 777,
                    minimum = 888
                },
            ttl = 3600
        },
        erldns_zone_parser:json_record_to_erlang(#{
            ~"name" => Name,
            ~"type" => ~"SOA",
            ~"ttl" => 3600,
            ~"data" => #{
                ~"mname" => ~"ns1.example.com",
                ~"rname" => ~"admin.example.com",
                ~"serial" => 12345,
                ~"refresh" => 555,
                ~"retry" => 666,
                ~"expire" => 777,
                ~"minimum" => 888
            },
            ~"context" => null
        })
    ).

json_record_ns_to_erlang(_) ->
    Name = ~"example.com",
    ?assertEqual(
        #dns_rr{
            name = Name,
            type = ?DNS_TYPE_NS,
            data = #dns_rrdata_ns{dname = ~"ns1.example.com"},
            ttl = 3600
        },
        erldns_zone_parser:json_record_to_erlang(#{
            ~"name" => Name,
            ~"type" => ~"NS",
            ~"ttl" => 3600,
            ~"data" => #{~"dname" => ~"ns1.example.com"},
            ~"context" => null
        })
    ).

json_record_a_to_erlang(_) ->
    Name = ~"example.com",
    ?assertEqual(
        #dns_rr{
            name = Name,
            type = ?DNS_TYPE_A,
            data = #dns_rrdata_a{ip = {1, 2, 3, 4}},
            ttl = 3600
        },
        erldns_zone_parser:json_record_to_erlang(#{
            ~"name" => Name,
            ~"type" => ~"A",
            ~"ttl" => 3600,
            ~"data" => #{~"ip" => ~"1.2.3.4"},
            ~"context" => null
        })
    ).

json_record_aaaa_to_erlang(_) ->
    Name = ~"example.com",
    ?assertEqual(
        #dns_rr{
            name = Name,
            type = ?DNS_TYPE_AAAA,
            data = #dns_rrdata_aaaa{ip = {0, 0, 0, 0, 0, 0, 0, 1}},
            ttl = 3600
        },
        erldns_zone_parser:json_record_to_erlang(#{
            ~"name" => Name,
            ~"type" => ~"AAAA",
            ~"ttl" => 3600,
            ~"data" => #{~"ip" => ~"::1"},
            ~"context" => null
        })
    ).

json_record_cds_to_erlang(_) ->
    Name = ~"example-dnssec.com",
    ?assertEqual(
        #dns_rr{
            name = Name,
            type = ?DNS_TYPE_CDS,
            data =
                #dns_rrdata_cds{
                    keytag = 0,
                    digest_type = 2,
                    alg = 8,
                    digest = binary:decode_hex(
                        ~"4315A7AD09AE0BEBA6CC3104BBCD88000ED796887F1C4D520A3A608D715B72CA"
                    )
                },
            ttl = 3600
        },
        erldns_zone_parser:json_record_to_erlang(#{
            ~"name" => Name,
            ~"type" => ~"CDS",
            ~"ttl" => 3600,
            ~"data" => #{
                ~"keytag" => 0,
                ~"digest_type" => 2,
                ~"alg" => 8,
                ~"digest" =>
                    ~"4315A7AD09AE0BEBA6CC3104BBCD88000ED796887F1C4D520A3A608D715B72CA"
            },
            ~"context" => null
        })
    ).

parse_json_keys_unsorted_proplists_time_unit(_) ->
    Base = #{
        ~"ksk" => ksk_private_key(),
        ~"ksk_alg" => 8,
        ~"ksk_keytag" => 37440,
        ~"zsk" => zsk_private_key(),
        ~"zsk_alg" => 8,
        ~"zsk_keytag" => 49016
    },
    %% nanoseconds
    ?assertMatch(
        [#keyset{inception = 1749478020, valid_until = 1781014020}],
        erldns_zone_parser:parse_keysets([
            Base#{
                ~"inception" => ~"2025-06-09T14:07:00.916361083Z",
                ~"until" => ~"2026-06-09T14:07:00.916361083Z"
            }
        ])
    ),
    %% microseconds
    ?assertMatch(
        [#keyset{inception = 1749478020, valid_until = 1781014020}],
        erldns_zone_parser:parse_keysets([
            Base#{
                ~"inception" => ~"2025-06-09T14:07:00.916361Z",
                ~"until" => ~"2026-06-09T14:07:00.916361Z"
            }
        ])
    ),
    %% milliseconds
    ?assertMatch(
        [#keyset{inception = 1749478020, valid_until = 1781014020}],
        erldns_zone_parser:parse_keysets([
            Base#{
                ~"inception" => ~"2025-06-09T14:07:00.916Z",
                ~"until" => ~"2026-06-09T14:07:00.916Z"
            }
        ])
    ),
    %% seconds
    ?assertMatch(
        [#keyset{inception = 1749478020, valid_until = 1781014020}],
        erldns_zone_parser:parse_keysets([
            Base#{
                ~"inception" => ~"2025-06-09T14:07:00Z",
                ~"until" => ~"2026-06-09T14:07:00Z"
            }
        ])
    ).

parse_json_keys_unsorted_proplists(_) ->
    ?assertEqual(
        [
            #keyset{
                key_signing_key = [
                    1025,
                    117942195211355436516708579275854541924575773884167758398377054474457061084450782563901956510831117716183526402173215071572529228555976594387632086643427143744605045813923857147839015187463121492324352653506190767692034127161982651669657643423469824721891177589201529187860925827553628207715191151413138514807,
                    105745246243156727959858716443424706369448913365414799968886354206854672328400262610952095642393948469436742208387497220268443279066285356333886719634448317208189715942402022382731037836531762881862458283240610274107136766709456566004076449761688996028612988763775001691587086168632010166111722279727494037097
                ],
                key_signing_key_tag = 37440,
                key_signing_alg = 8,
                zone_signing_key = [
                    513,
                    9170529505818457214552347052832728824507861128011245996056627438339703762731346681703094163316286362641501571794424157931806097889892946273849538579240359,
                    5130491166023191463112131781994138738077497356216817935415696052248528225933414267440640871636073852185344964288812312263453467652493907737029964715172561
                ],
                zone_signing_key_tag = 49016,
                zone_signing_alg = 8,
                inception = 1479123418,
                valid_until = 1486899418
            }
        ],
        erldns_zone_parser:parse_keysets([
            #{
                ~"ksk" => ksk_private_key(),
                ~"ksk_alg" => 8,
                ~"ksk_keytag" => 37440,
                ~"zsk" => zsk_private_key(),
                ~"zsk_alg" => 8,
                ~"zsk_keytag" => 49016,
                ~"inception" => ~"2016-11-14T11:36:58.851612Z",
                ~"until" => ~"2017-02-12T11:36:58.849384Z"
            }
        ])
    ).

loader_coverage(_) ->
    erldns_zone_loader:start_link(),
    gen_server:call(erldns_zone_loader, anything),
    gen_server:cast(erldns_zone_loader, anything),
    ?assert(erlang:is_process_alive(whereis(erldns_zone_loader))).

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
    ?assertMatch(4, erldns_zone_loader:load_zones()).

cache_coverage(_) ->
    gen_server:call(erldns_zone_cache, anything),
    gen_server:cast(erldns_zone_cache, anything),
    ?assert(erlang:is_process_alive(whereis(erldns_zone_cache))).

lookup_zone(_) ->
    ?assertMatch(zone_not_found, erldns_zone_cache:lookup_zone(~"rand.example.net")),
    ?assertMatch(#zone{}, erldns_zone_cache:lookup_zone([~"example", ~"com"])),
    ?assertMatch(#zone{}, erldns_zone_cache:lookup_zone(~"example.com")),
    ?assertMatch(zone_not_found, erldns_zone_cache:lookup_zone(~"EXAMPLE.COM")).

get_zone_records(_) ->
    Zone = erldns_zone_cache:lookup_zone(~"example.com"),
    ?assertMatch([], erldns_zone_cache:get_zone_records(~"rand.example.net")),
    ?assertMatch([], erldns_zone_cache:get_zone_records(~"EXAMPLE.COM")),
    ?assertMatch(L when 9 =:= length(L), erldns_zone_cache:get_zone_records([~"example", ~"com"])),
    ?assertMatch(L when 9 =:= length(L), erldns_zone_cache:get_zone_records(~"example.com")),
    ?assertMatch(L when 9 =:= length(L), erldns_zone_cache:get_zone_records(Zone)).

get_records_by_name(_) ->
    NxName = dns:dname_to_lower(~"nxname.a1.example.net"),
    NxName2 = dns:dname_to_lower(~"nxname.a1.example.com"),
    Name = dns:dname_to_lower(~"a1.example.com"),
    Labels = dns:dname_to_lower_labels(~"a1.example.com"),
    Zone = erldns_zone_cache:lookup_zone(~"example.com"),
    ?assertMatch([], erldns_zone_cache:get_records_by_name(NxName)),
    ?assertMatch([#dns_rr{}], erldns_zone_cache:get_records_by_name(Labels)),
    ?assertMatch([#dns_rr{}], erldns_zone_cache:get_records_by_name(Name)),
    ?assertMatch([], erldns_zone_cache:get_records_by_name(Zone, NxName)),
    ?assertMatch([], erldns_zone_cache:get_records_by_name(Zone, NxName2)),
    ?assertMatch([#dns_rr{}], erldns_zone_cache:get_records_by_name(Zone, Name)),
    ?assertMatch([#dns_rr{}], erldns_zone_cache:get_records_by_name(Zone, Labels)).

get_records_by_name_and_type(_) ->
    Type = ?DNS_TYPE_A,
    NxName = dns:dname_to_lower(~"nxname.a1.example.net"),
    Name = dns:dname_to_lower(~"a1.example.com"),
    Labels = dns:dname_to_lower_labels(~"a1.example.com"),
    Zone = erldns_zone_cache:lookup_zone(~"example.com"),
    ?assertMatch([], erldns_zone_cache:get_records_by_name_and_type(NxName, Type)),
    ?assertMatch([#dns_rr{}], erldns_zone_cache:get_records_by_name_and_type(Labels, Type)),
    ?assertMatch([#dns_rr{}], erldns_zone_cache:get_records_by_name_and_type(Name, Type)),
    ?assertMatch([#dns_rr{}], erldns_zone_cache:get_records_by_name_and_type(Zone, Name, Type)),
    ?assertMatch([#dns_rr{}], erldns_zone_cache:get_records_by_name_and_type(Zone, Labels, Type)).

get_records_by_name_ent(_) ->
    Ent = dns:dname_to_lower(~"a2.a1.example.com"),
    Labels = dns:dname_to_lower_labels(Ent),
    Zone = erldns_zone_cache:lookup_zone(~"example.com"),
    ?assertMatch([#dns_rr{}, #dns_rr{}], erldns_zone_cache:get_records_by_name_ent(Zone, Ent)),
    ?assertMatch([#dns_rr{}, #dns_rr{}], erldns_zone_cache:get_records_by_name_ent(Zone, Labels)).

get_records_by_name_wildcard(_) ->
    Record = dns:dname_to_lower(~"a3.a2.a1.example.com"),
    Ent = dns:dname_to_lower(~"a2.a1.example.com"),
    Wild = dns:dname_to_lower(~"a.a-wild.example.com"),
    Labels = dns:dname_to_lower_labels(Wild),
    Zone = erldns_zone_cache:lookup_zone(~"example.com"),
    ?assertMatch([], erldns_zone_cache:get_records_by_name_wildcard(Zone, Ent)),
    ?assertMatch([], erldns_zone_cache:get_records_by_name_wildcard(Zone, Record)),
    ?assertMatch([#dns_rr{}], erldns_zone_cache:get_records_by_name_wildcard(Zone, Wild)),
    ?assertMatch([#dns_rr{}], erldns_zone_cache:get_records_by_name_wildcard(Zone, Labels)).

get_records_by_name_wildcard_strict(_) ->
    Record = dns:dname_to_lower(~"a3.a2.a1.example.com"),
    Ent = dns:dname_to_lower(~"a2.a1.example.com"),
    Wild = dns:dname_to_lower(~"a.a-wild.example.com"),
    Labels = dns:dname_to_lower_labels(Wild),
    Zone = erldns_zone_cache:lookup_zone(~"example.com"),
    ?assertMatch([#dns_rr{}], erldns_zone_cache:get_records_by_name_wildcard_strict(Zone, Ent)),
    ?assertMatch([#dns_rr{}], erldns_zone_cache:get_records_by_name_wildcard_strict(Zone, Record)),
    ?assertMatch([#dns_rr{}], erldns_zone_cache:get_records_by_name_wildcard_strict(Zone, Wild)),
    ?assertMatch([#dns_rr{}], erldns_zone_cache:get_records_by_name_wildcard_strict(Zone, Labels)).

get_authoritative_zone(_) ->
    NxName = dns:dname_to_lower(~"example.net"),
    Labels = dns:dname_to_lower_labels(~"a.a-wild.example.com"),
    Name = dns:dname_to_lower(~"n4.n3.n2.n1.example.com"),
    ?assertMatch(zone_not_found, erldns_zone_cache:get_authoritative_zone(NxName)),
    ?assertMatch(#zone{}, erldns_zone_cache:get_authoritative_zone(Labels)),
    ?assertMatch(#zone{}, erldns_zone_cache:get_authoritative_zone(Name)).

get_delegations(_) ->
    NxName = dns:dname_to_lower(~"none.example.net"),
    Labels = dns:dname_to_lower_labels(~"delegation.example.com"),
    Name = dns:dname_to_lower(~"delegation.example.com"),
    ?assertMatch([], erldns_zone_cache:get_delegations(NxName)),
    ?assertMatch([#dns_rr{}], erldns_zone_cache:get_delegations(Labels)),
    ?assertMatch([#dns_rr{}], erldns_zone_cache:get_delegations(Name)).

is_in_any_zone(_) ->
    NxName = dns:dname_to_lower(~"nxname.a1.example.net"),
    Name = dns:dname_to_lower(~"a1.example.com"),
    Labels = dns:dname_to_lower_labels(Name),
    ?assertMatch(false, erldns_zone_cache:is_in_any_zone(NxName)),
    ?assertMatch(true, erldns_zone_cache:is_in_any_zone(Name)),
    ?assertMatch(true, erldns_zone_cache:is_in_any_zone(Labels)).

is_name_in_zone(_) ->
    NxName = dns:dname_to_lower(~"a2.a1.example.net"),
    Ent = dns:dname_to_lower(~"a2.a1.example.com"),
    Name = dns:dname_to_lower(~"a3.a2.a1.example.com"),
    Wild = dns:dname_to_lower(~"a.a-wild.example.com"),
    Labels = dns:dname_to_lower_labels(Name),
    Zone = erldns_zone_cache:lookup_zone(~"example.com"),
    ?assertMatch(false, erldns_zone_cache:is_name_in_zone(Zone, NxName)),
    ?assertMatch(false, erldns_zone_cache:is_name_in_zone(Zone, Ent)),
    ?assertMatch(false, erldns_zone_cache:is_name_in_zone(Zone, Wild)),
    ?assertMatch(true, erldns_zone_cache:is_name_in_zone(Zone, Name)),
    ?assertMatch(true, erldns_zone_cache:is_name_in_zone(Zone, Labels)).

is_record_name_in_zone(_) ->
    NxName = dns:dname_to_lower(~"a2.a1.example.net"),
    Ent = dns:dname_to_lower(~"a2.a1.example.com"),
    Name = dns:dname_to_lower(~"a1.example.com"),
    Wild = dns:dname_to_lower(~"a.a-wild.example.com"),
    Labels = dns:dname_to_lower_labels(Name),
    Zone = erldns_zone_cache:lookup_zone(~"example.com"),
    ?assertMatch(false, erldns_zone_cache:is_record_name_in_zone(Zone, NxName)),
    ?assertMatch(false, erldns_zone_cache:is_record_name_in_zone(Zone, Ent)),
    ?assertMatch(true, erldns_zone_cache:is_record_name_in_zone(Zone, Wild)),
    ?assertMatch(true, erldns_zone_cache:is_record_name_in_zone(Zone, Name)),
    ?assertMatch(true, erldns_zone_cache:is_record_name_in_zone(Zone, Labels)).

is_record_name_in_zone_strict(_) ->
    NxName = dns:dname_to_lower(~"a2.a1.example.net"),
    Ent = dns:dname_to_lower(~"a2.a1.example.com"),
    Name = dns:dname_to_lower(~"a1.example.com"),
    Labels = dns:dname_to_lower_labels(Name),
    Zone = erldns_zone_cache:lookup_zone(~"example.com"),
    ?assertMatch(false, erldns_zone_cache:is_record_name_in_zone_strict(Zone, NxName)),
    ?assertMatch(true, erldns_zone_cache:is_record_name_in_zone_strict(Zone, Ent)),
    ?assertMatch(true, erldns_zone_cache:is_record_name_in_zone_strict(Zone, Name)),
    ?assertMatch(true, erldns_zone_cache:is_record_name_in_zone_strict(Zone, Labels)).

put_zone(_) ->
    ZoneName = dns:dname_to_lower(~"a1.put_zone.com"),
    RR = #dns_rr{
        data = #dns_rrdata_a{ip = {5, 5, 5, 5}},
        name = ~"a1.put_zone.com",
        ttl = 5,
        type = ?DNS_TYPE_A
    },
    SOA = #dns_rr{
        name = ZoneName,
        type = ?DNS_TYPE_SOA,
        data =
            #dns_rrdata_soa{
                mname = ~"ns1.put_zone.com",
                rname = ~"admin.put_zone.com",
                serial = 12345,
                refresh = 555,
                retry = 666,
                expire = 777,
                minimum = 888
            },
        ttl = 3600
    },
    Z = erldns_zone_codec:build_zone(ZoneName, ~"", [SOA, RR], []),
    ?assertMatch(ok, erldns_zone_cache:put_zone(Z)),
    ?assertMatch(#zone{}, erldns_zone_cache:get_authoritative_zone(~"a1.put_zone.com")),
    ?assertMatch(ok, erldns_zone_cache:put_zone({~"a2.put_zone.com", ~"", []})),
    ?assertMatch(not_authoritative, erldns_zone_cache:get_authoritative_zone(~"a2.put_zone.com")),
    ?assertMatch(ok, erldns_zone_cache:put_zone({~"a3.put_zone.com", ~"", [], []})),
    ?assertMatch(not_authoritative, erldns_zone_cache:get_authoritative_zone(~"a3.put_zone.com")).

put_zone_rrset(_) ->
    ZoneNameNet = dns:dname_to_lower(~"example.net"),
    ZoneNet = erldns_zone_codec:build_zone(ZoneNameNet, ~"irrelevantDigest", [], []),
    ?assertMatch(zone_not_found, erldns_zone_cache:put_zone_rrset(ZoneNet, ~"a.example.net", 5, 1)),
    ZoneName = dns:dname_to_lower(~"example.com"),
    ZoneLabels = dns:dname_to_labels(ZoneName),
    ZoneBase = erldns_zone_cache:get_authoritative_zone(ZoneLabels),
    Record = #dns_rr{
        data = #dns_rrdata_cname{dname = ~"google.com"},
        name = ~"cname.example.com",
        ttl = 5,
        type = ?DNS_TYPE_CNAME
    },
    Zone = erldns_zone_codec:build_zone(ZoneName, ~"irrelevantDigest", [Record], []),
    ?assertMatch(
        ok,
        erldns_zone_cache:put_zone_rrset(
            {ZoneName, ~"irrelevantDigest", [Record], []}, ~"cname.example.com", ?DNS_TYPE_CNAME, 1
        )
    ),
    ?assertMatch(
        ok,
        erldns_zone_cache:put_zone_rrset(
            {ZoneName, ~"irrelevantDigest", [Record]}, ~"cname.example.com", ?DNS_TYPE_CNAME, 1
        )
    ),
    ?assertMatch(ok, erldns_zone_cache:put_zone_rrset(Zone, ~"cname.example.com", 5, 1)),
    ZoneModified = erldns_zone_cache:get_authoritative_zone(ZoneLabels),
    % There should be no change in record count
    ?assertEqual(ZoneBase#zone.record_count, ZoneModified#zone.record_count).

put_zone_rrset_records_count_with_existing_rrset(_) ->
    ZoneName = dns:dname_to_lower(~"example.com"),
    ZoneLabels = dns:dname_to_labels(ZoneName),
    ZoneBase = erldns_zone_cache:get_authoritative_zone(ZoneLabels),
    erldns_zone_cache:put_zone_rrset(
        {ZoneName, ~"irrelevantDigest",
            [
                #dns_rr{
                    data = #dns_rrdata_cname{dname = ~"google.com"},
                    name = ~"cname.example.com",
                    ttl = 5,
                    type = ?DNS_TYPE_CNAME
                }
            ],
            []},
        ~"cname.example.com",
        ?DNS_TYPE_CNAME,
        1
    ),
    ZoneModified = erldns_zone_cache:get_authoritative_zone(ZoneLabels),
    % There should be no change in record count
    ?assertEqual(ZoneBase#zone.record_count, ZoneModified#zone.record_count).

put_zone_rrset_records_count_with_new_rrset(_) ->
    ZoneName = dns:dname_to_lower(~"example.com"),
    ZoneLabels = dns:dname_to_labels(ZoneName),
    ZoneBase = erldns_zone_cache:get_authoritative_zone(ZoneLabels),
    erldns_zone_cache:put_zone_rrset(
        {ZoneName, ~"irrelevantDigest",
            [
                #dns_rr{
                    data = #dns_rrdata_a{ip = {5, 5, 5, 5}},
                    name = ~"put_zone_rrset_records_count_with_new_rrset.example.com",
                    ttl = 5,
                    type = ?DNS_TYPE_A
                }
            ],
            []},
        ~"put_zone_rrset_records_count_with_new_rrset.example.com",
        ?DNS_TYPE_A,
        1
    ),
    ZoneModified = erldns_zone_cache:get_authoritative_zone(ZoneLabels),
    % New RRSet is being added with one record we should see an increase by 1
    ?assertEqual(ZoneBase#zone.record_count + 1, ZoneModified#zone.record_count).

put_zone_rrset_records_count_matches_cache(_) ->
    ZoneName = dns:dname_to_lower(~"example.com"),
    ZoneLabels = dns:dname_to_labels(ZoneName),
    erldns_zone_cache:put_zone_rrset(
        {ZoneName, ~"irrelevantDigest",
            [
                #dns_rr{
                    data = #dns_rrdata_a{ip = {5, 5, 5, 5}},
                    name = ~"put_zone_rrset_records_count_matches_cache.example.com",
                    ttl = 5,
                    type = ?DNS_TYPE_A
                }
            ],
            []},
        ~"put_zone_rrset_records_count_matches_cache.example.com",
        ?DNS_TYPE_A,
        1
    ),
    ZoneModified = erldns_zone_cache:get_authoritative_zone(ZoneLabels),
    % New RRSet is being added with one record we should see an increase by 1
    ?assertEqual(
        length(erldns_zone_cache:get_zone_records(ZoneName)), ZoneModified#zone.record_count
    ).

put_zone_rrset_records_count_with_dnssec_zone_and_new_rrset(_) ->
    ZoneName = dns:dname_to_lower(~"example-dnssec.com"),
    ZoneLabels = dns:dname_to_labels(ZoneName),
    Zone = erldns_zone_cache:get_authoritative_zone(ZoneLabels),
    erldns_zone_cache:put_zone_rrset(
        {ZoneName, ~"irrelevantDigest",
            [
                #dns_rr{
                    data = #dns_rrdata_cname{dname = ~"google.com"},
                    name = ~"cname.example-dnssec.com",
                    ttl = 60,
                    type = ?DNS_TYPE_CNAME
                }
            ],
            []},
        ~"cname.example-dnssec.com",
        ?DNS_TYPE_CNAME,
        1
    ),
    ZoneModified = erldns_zone_cache:get_authoritative_zone(ZoneLabels),
    % New RRSet entry for the CNAME + 1 RRSig record
    ?assertEqual(Zone#zone.record_count + 2, ZoneModified#zone.record_count).

delete_zone_rrset_records_count_width_existing_rrset(_) ->
    ZoneName = dns:dname_to_lower(~"example.com"),
    ZoneLabels = dns:dname_to_labels(ZoneName),
    ZoneBase = erldns_zone_cache:get_authoritative_zone(ZoneLabels),
    erldns_zone_cache:delete_zone_rrset(
        ZoneName,
        ~"irrelevantDigest",
        dns:dname_to_lower(~"cname.example.com"),
        ?DNS_TYPE_CNAME,
        1
    ),
    ZoneModified = erldns_zone_cache:get_authoritative_zone(ZoneLabels),
    % Deletes a CNAME RRSet with one record
    ?assertEqual(ZoneBase#zone.record_count - 1, ZoneModified#zone.record_count).

delete_zone_rrset_records_count_width_dnssec_zone_and_existing_rrset(_) ->
    ZoneName = dns:dname_to_lower(~"example-dnssec.com"),
    ZoneLabels = dns:dname_to_labels(ZoneName),
    ZoneBase = erldns_zone_cache:get_authoritative_zone(ZoneLabels),
    erldns_zone_cache:delete_zone_rrset(
        ZoneName,
        ~"irrelevantDigest",
        dns:dname_to_lower(~"cname2.example-dnssec.com"),
        ?DNS_TYPE_CNAME,
        2
    ),
    ZoneModified = erldns_zone_cache:get_authoritative_zone(ZoneLabels),
    % Deletes a CNAME RRSet with one record + RRSig
    ?assertEqual(ZoneBase#zone.record_count - 2, ZoneModified#zone.record_count).

delete_zone_rrset_records_count_matches_cache(_) ->
    ZoneName = dns:dname_to_lower(~"example-dnssec.com"),
    ZoneLabels = dns:dname_to_labels(ZoneName),
    erldns_zone_cache:delete_zone_rrset(
        ZoneName,
        ~"irrelevantDigest",
        dns:dname_to_lower(~"cname2.example-dnssec.com"),
        ?DNS_TYPE_CNAME,
        2
    ),
    ZoneModified = erldns_zone_cache:get_authoritative_zone(ZoneLabels),
    % Deletes a CNAME RRSet with one record + RRSig
    ?assertEqual(
        length(erldns_zone_cache:get_zone_records(ZoneName)), ZoneModified#zone.record_count
    ).

delete_zone_rrset_records_count_underflow(_) ->
    ZoneName = dns:dname_to_lower(~"example-dnssec.com"),
    ZoneLabels = dns:dname_to_labels(ZoneName),
    ZoneBase = erldns_zone_cache:get_authoritative_zone(ZoneLabels),
    erldns_zone_cache:delete_zone_rrset(
        ZoneName,
        ~"irrelevantDigest",
        dns:dname_to_lower(~"cname2.example-dnssec.com"),
        ?DNS_TYPE_CNAME,
        1
    ),
    ZoneModified = erldns_zone_cache:get_authoritative_zone(ZoneLabels),
    % Deletes a CNAME RRSet with one record
    ?assertEqual(ZoneBase#zone.record_count, ZoneModified#zone.record_count).

delete_zone_rrset_records_zone_not_found(_) ->
    ZoneName = dns:dname_to_lower(~"example-dnssec.net"),
    Ret = erldns_zone_cache:delete_zone_rrset(
        ZoneName,
        ~"irrelevantDigest",
        dns:dname_to_lower(~"cname2.example-dnssec.com"),
        ?DNS_TYPE_CNAME,
        1
    ),
    ?assertEqual(zone_not_found, Ret).

setup_test(Config, _) ->
    {ok, _} = erldns_zone_codec:start_link(),
    {ok, _} = erldns_zone_cache:start_link(),
    DataDir = proplists:get_value(data_dir, Config),
    application:set_env(erldns, zones, #{path => filename:join(DataDir, "standard.json")}),
    ?assertMatch(1, erldns_zone_loader:load_zones()),
    application:set_env(erldns, zones, #{path => filename:join(DataDir, "dnssec-zone.json")}),
    ?assertMatch(1, erldns_zone_loader:load_zones()).

ksk_private_key() ->
    <<
        "-----BEGIN RSA PRIVATE KEY-----\nMIICXAIBAAKBgQCn9Iv82vkFiv8ts8K9jzUzfp3UEZx+76r+X9A4GOFfYbx3USCh\nEW0fLYT/Q"
        "kAM8/SiTkEXzZPqhrV083mp5VLYNLxic2ii6DrwvyGpENVPJnDQMu+C\nfKMyb9IWcm9MkeHh8t/ovsCQAEJWIPTnzv8rlQcDU44c3qgTpHS"
        "U8htjdwICBAEC\ngYEAlpYTHWYrcd0HQXO3F9lPqwwfHUt7VBaSEUYrk3N3ZYCWvmV1qyKbB/kb1SBs\n4GfW1vP966HXCffnX92LDXYxi7I"
        "t3TJaKmo8aF/leN7w8WLNJXUayEoQKUfKLprj\nN14Jx/tgMu7I/BOoHId8b7e57pBKtDiSF6WWn3K7tNPbfmkCQQDST41m62mC4MAa\nDsU"
        "dyM0Vg/tjduGqnygryCDEXDabdg95a3wMk0SQCQzZFHGNYnsXcffTqGs/y+5w\nQWxyOGSNAkEAzHFkDJla30NiiKvhu7dY+0+dGrfMA7pNU"
        "h+LGdXe5QFdjwwxqPbF\n7NMGXKMdB8agSCxGZC3bxdvYNF9LULzhEwJABpDYNSoQx+UMvaEN5XTpLmCHuS1r\nsmhfKZPcDx8Z7mAYda3wZ"
        "EuHQq+cf6i5XhOO9P5QKpKeslHLAMHa7NaNgQJBAI03\nGGacYLwui32fbzb8BYRg82Kga/OW6btY+O6hNs6iSR2gBlQ9j3Tgrzo+N4R/NQS"
        "l\nc05wGO2RnBUwlu0XUckCQHfHsWHVrrADTpalbv+FTDyWd0ouHXBmDecVZh3e7/ue\ncdMoblzeasvgp8CjFa9U+uDozY+aL6TNIpG++nn"
        "4lNw=\n-----END RSA PRIVATE KEY-----\n"
    >>.

zsk_private_key() ->
    <<
        "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK8YnU+YqBxD/EDwVeHZsJillAJ80PCnLU+/rlGrlzgw+eabF8jT\nCaEwnpE74"
        "YHCLegKAAn+efeZrT/EBBrzlacCAgIBAkBh9VGFW2SJk1I9SBQaDIA9\nchdrrx+PHibSyozwT4eAPmd6OFoLausc7ls6v9evPeb+Yj3g0JX"
        "vTGp6BgNhFqLR\nAiEA1+ievAEBVM6IlOmpiTwlaWe/HV6MokBBq1G/tvJS0M8CIQDPm/DUsoTEv/Jj\n6O3U9hNcPLbvKMMGld2wbf7nrQm"
        "zqQIhAJrhwTaFdjnXhmfUB9a33vRIbSaIsLxA\nDyuM+03XP+YhAiEAmJIJz7WX9uPkCIy8wO655Hh4dt4UkBFRE98OqkHIwGkCIFFv\nN8r"
        "JojI+oEiJyNjEjWZD4qoUMUp3+YBl0htAJUE2\n-----END RSA PRIVATE KEY-----\n"
    >>.

input() ->
    ~"""
    {
      "name": "example.com",
      "records": [
        {
          "context": [
            "anycast"
          ],
          "data": {
            "expire": 604800,
            "minimum": 300,
            "mname": "ns1.dnsimple.com",
            "refresh": 86400,
            "retry": 7200,
            "rname": "admin.dnsimple.com",
            "serial": 1597990915
          },
          "name": "example.com",
          "ttl": 3600,
          "type": "SOA"
        },
        {
          "context": [
            "anycast"
          ],
          "data": { "dname": "ns1.dnsimple.com" },
          "name": "example.com",
          "ttl": 3600,
          "type": "NS"
        },
        {
          "context": [
            "anycast"
          ],
          "data": { "dname": "ns2.dnsimple.com" },
          "name": "example.com",
          "ttl": 3600,
          "type": "NS"
        },
        {
          "context": [
            "anycast"
          ],
          "data": { "dname": "ns3.dnsimple.com" },
          "name": "example.com",
          "ttl": 3600,
          "type": "NS"
        },
        {
          "context": [
            "anycast"
          ],
          "data": { "dname": "ns4.dnsimple.com" },
          "name": "example.com",
          "ttl": 3600,
          "type": "NS"
        },
        {
          "context": [],
          "data": { "ip": "5.4.3.2" },
          "name": "*.qa.example.com",
          "ttl": 3600,
          "type": "A"
        },
        {
          "context": [],
          "data": { "ip": "1.2.3.4" },
          "name": "example.com",
          "ttl": 3600,
          "type": "A"
        },
        {
          "context": [],
          "data": { "ip": "2001:db8:0:0:0:0:2:1" },
          "name": "example.com",
          "ttl": 3600,
          "type": "AAAA"
        },
        {
          "context": [],
          "data": { "dname": "example.com" },
          "name": "www.example.com",
          "ttl": 3600,
          "type": "CNAME"
        },
        {
          "context": [],
          "data": {
            "flags": 0,
            "tag": "issue",
            "value": "comodoca.com"
          },
          "name": "example.com",
          "ttl": 3600,
          "type": "CAA"
        },
        {
          "context": [],
          "data": {
            "exchange": "mailserver.foo.com",
            "preference": 10
          },
          "name": "example.com",
          "ttl": 3600,
          "type": "MX"
        },
        {
          "context": [],
          "data": {
            "txts": ["this is a test"]
          },
          "name": "example.com",
          "ttl": 3600,
          "type": "TXT"
        },
        {
          "context": [],
          "data": {
            "txts": ["v=spf1 a mx ~all"]
          },
          "name": "example.com",
          "ttl": 3600,
          "type": "SPF"
        },
        {
          "context": [],
          "data": { "txts": ["v=spf1 a mx ~all"] },
          "name": "example.com",
          "ttl": 3600,
          "type": "TXT"
        },
        {
          "context": [],
          "data": {
            "alg": 3,
            "fp": "ABC123",
            "fptype": 2
          },
          "name": "example.com",
          "ttl": 3600,
          "type": "SSHFP"
        },
        {
          "context": [],
          "data": {
            "port": 3333,
            "priority": 20,
            "target": "example.net",
            "weight": 10
          },
          "name": "_foo._bar.example.com",
          "ttl": 3600,
          "type": "SRV"
        },
        {
          "context": [],
          "data": {
            "flags": "u",
            "order": 5,
            "preference": 10,
            "regexp": "https://example\\.net",
            "replacement": "example.org",
            "services": "foo"
          },
          "name": "example.com",
          "ttl": 3600,
          "type": "NAPTR"
        },
        {
          "context": [
            "SV1"
          ],
          "data": { "ip": "5.5.5.5" },
          "name": "example.com",
          "ttl": 3600,
          "type": "A"
        },
        {
          "context": [],
          "data": {
            "cpu": "cpu",
            "os": "os"
          },
          "name": "example.com",
          "ttl": 3600,
          "type": "HINFO"
        },
        {
          "context": [],
          "data": {
            "alg": 8,
            "flags": 257,
            "key_tag": 0,
            "protocol": 3,
            "public_key": "AwEAAcFwY/oPw5JPGTT2qf2opNMpNAopxC6xWvGO2QAKA7ERAzKYsiXt7j1/ttJjgnLS2Qj30bbnRyazj7Lg9oZcmiJ4/cfBHLBczzaxtqwZrxX1rcQz1OpU/hnq4W5Rsk2i1hxdpRjLnVfddVFD3GDDgIEjvaiKtaJcA61WtDDA08Ba90S7czkUh2Nfv7cTYEFhjnx0bdtapwRQEirHjzyAJqs="
          },
          "name": "example.com",
          "ttl": 3600,
          "type": "DNSKEY"
        },
        {
          "context": [],
          "data": {
            "alg": 8,
            "flags": 256,
            "key_tag": 0,
            "protocol": 3,
            "public_key": "AwEAAddpSYg8TvfhxHRTG1zrCPXWuG/gN0/q2dzQtM3um6zVl0sIFQKWfcdcowpim13K4euSqzltBB+XwDjv9fbWb6x i0mTF0c0NgOQ/Ctf5sQOBtGBkopbQgxDuXDTC1jJaUTVlzjN9m8KYoVacTbhMFBAtwn6LC1sEYfwiCsADk3cV"
          },
          "name": "example.com",
          "ttl": 3600,
          "type": "DNSKEY"
        },
        {
          "context": [],
          "data": {
            "alg": 8,
            "flags": 257,
            "key_tag": 0,
            "protocol": 3,
            "public_key": "AwEAAbPhmoznnzWMbx0h+RcyI+Bi2tzlOnd/AbZK7iXgGY62lZo442+6TpZNlkeFEqk+YKxUce70RWkG/LHuJeywfmPySSra2rYG3P3ntAgbcrbwMDa9cmYVEnS2+ObEFeqowcoe4kjzy5249skMn9Hl8D5pWXp0EbzOSuKSRDFEaGfNycvc8/VfcEi8LwUffTkq8ZFE9P6QEqyeDM4yO2XmoSs="
          },
          "name": "example.com",
          "ttl": 3600,
          "type": "DNSKEY"
        },
        {
          "context": [],
          "data": {
            "alg": 8,
            "flags": 256,
            "key_tag": 0,
            "protocol": 3,
            "public_key": "AwEAAdAKvoBtIj2GzLpawDNm/ztuuxIbU2lticK5lMwisLN8HY1QXjdFk+pOCHp1XsS2Odd6rQyy/IJvBEFFeeZDoyUeoa2i93STTETMZZ/dX1YtJPQnw8MJ0buxfeCxZGRVmbpu4p+YeZ2AFN1ZSziKD7HununBWFXQc7vHRK0QSBTH"
          },
          "name": "example.com",
          "ttl": 3600,
          "type": "DNSKEY"
        },
        {
          "context": [],
          "data": {
            "alg": 8,
            "flags": 257,
            "key_tag": 0,
            "protocol": 3,
            "public_key": "AwEAAbPhmoznnzWMbx0h+RcyI+Bi2tzlOnd/AbZK7iXgGY62lZo442+6TpZNlkeFEqk+YKxUce70RWkG/LHuJeywfmPySSra2rYG3P3ntAgbcrbwMDa9cmYVEnS2+ObEFeqowcoe4kjzy5249skMn9Hl8D5pWXp0EbzOSuKSRDFEaGfNycvc8/VfcEi8LwUffTkq8ZFE9P6QEqyeDM4yO2XmoSs="
          },
          "name": "example.com",
          "ttl": 3600,
          "type": "CDNSKEY"
        },
        {
          "context": [],
          "data": {
            "alg": 8,
            "digest": "933FE542B3351226B7D0460EBFCB3D48909106B052E803E04063ACC179D3664B",
            "digest_type": 2,
            "flags": 61079,
            "keytag": 0
          },
          "name": "example.com",
          "ttl": 3600,
          "type": "CDS"
        }
      ],
      "keys": [
        {
          "inception": "2020-12-02T08:38:09.631363Z",
          "ksk": "-----BEGIN RSA PRIVATE KEY-----\nMIIC7AIBAAKBoQDBcGP6D8OSTxk09qn9qKTTKTQKKcQusVrxjtkACgOxEQMymLIl\n7e49f7bSY4Jy0tkI99G250cms4+y4PaGXJoieP3HwRywXM82sbasGa8V9a3EM9Tq\nVP4Z6uFuUbJNotYcXaUYy51X3XVRQ9xgw4CBI72oirWiXAOtVrQwwNPAWvdEu3M5\nFIdjX7+3E2BBYY58dG3bWqcEUBIqx488gCarAgMBAAECgaBZk/9oVJZ/kYudwEB2\nS/uQIbuMnUzRRqZTyI/q+bg97h/p9VZCRE2YQyVZhmVpYQTKp2CBb9a+MFbyQkVH\ncWibYCY9s8riTQhUTrXGOtqesumWkTDdacbyuMjobme4WPX8L3xlX5spttpkZQfc\neC0hpwX8bKRUuQifHPAhjuYxcVWIOZk5OaprHxwoXtM0oSNPaGiPCM0fq4GmnF1n\n3Eg5AlEA4aB6F0pG5ajnycvWETz/WZpv/wkcO0UlbgSFlx2OD545CKYcZlbx22bl\nWvYHvkio1AAg03oFQfXNtcl6274s2WFEJw5v0UBk0VHGq2zeTDUCUQDbeqkepngF\njyuRSzfViuA3jpO/8zmFm6Fpr5eCNgqEf+uC7zF+dg9bnnfEA88+x8IjuioRvbx7\nkSMjiIijQUgo103vXadpPhBXFx7EadBDXwJQV0wtEQfXKJLSo/xvJhpQvk2H2cif\nmLsnQUsUmSSBS7+vV45V3K71QyurwCcDVfdtAyHNkaVblWrSneyH0a/iUHVW1jm6\nv97HY0ndsYQc+qUCUQC3Al24wAh+YjZq7bR97FIwIUQUH4TMYsxCKveDzPoSJ/RC\ndp7nmxwNQmMNYDvUVo8MaXQg3PwocQpC29tLfejknTtQJ+CrgePwKsgt8SmGswJQ\nVt10NCsGdK7ACTz1Asfcb4JQUYM/d14ofhJRHptROLE93gHx9He+JGq4ET74YQvd\nD8V0L923eLixsHh5I5t/1QEVwbpeGcDhb+j8LeVvV8w=\n-----END RSA PRIVATE KEY-----\n",
          "ksk_alg": 8,
          "ksk_keytag": 57949,
          "until": "2021-03-02T08:38:09.630312Z",
          "zsk": "-----BEGIN RSA PRIVATE KEY-----\nMIICXQIBAAKBgQDXaUmIPE734cR0Uxtc6wj11rhv4DdP6tnc0LTN7pus1ZdLCBUC\nln3HXKMKYptdyuHrkqs5bQQfl8A47/X21m+sYtJkxdHNDYDkPwrX+bEDgbRgZKKW\n0IMQ7lw0wtYyWlE1Zc4zfZvCmKFWnE24TBQQLcJ+iwtbBGH8IgrAA5N3FQIDAQAB\nAoGBAIozFGgBOTCzedSflQiSChefAIlWMmZlaAzRIY6VLO8/wWbz8nbMkjmbZ0a8\naK1OAo+ec5fOJz0VoM9mtEj+3nlvQoJBw1ubBy4o3yr6X8dOwyEqtH8Riciv9XlE\nDg6uQH8u52CErzYd7io9NVn+vQZEFdw1kwy9bHl6Zb+SwwWpAkEA69Dw7b2VC4aP\na/wr0/xME2hXb7qf2YsH3GreJHTH1D7fdQozKdw4o8tUFjKvOTy827N2X7PSp+cW\nXYzk7Pp7nwJBAOnZPx2KK58IqBdmRpSfdQmstbC9k9SWby1NxH7xerepdRr+Fvnr\nSVZo4JcIyWk1FVUHd9ZNIagIJZhE2tRWkMsCQDPX05/wtfu6sX1ECz6nkPITVmWx\n2cKx1iCXPg81vVjkGaxZebYSPEGGSg43Rl6HA94pLjUMC5vuKfSXLR0MVHECQEWu\n6ADccH02bihy4KtfDNgyL/4Xr9qUbVK5rskJGkFqbKv7dUtJ0pO+Mtau1p3UJKQu\n0oX4fAP/UXybX/4QQZsCQQCcym4PAXhtW5U1FmV/dGCMb8rufZt7bmHHPulrAIVv\n5Zse+HIV/u0c36RRHSRuW4MPICrHE7Uf5B7/7TcWp3nZ\n-----END RSA PRIVATE KEY-----\n",
          "zsk_alg": 8,
          "zsk_keytag": 15271
        },
        {
          "inception": "2020-12-02T10:45:48.279746Z",
          "ksk": "-----BEGIN RSA PRIVATE KEY-----\nMIIC7QIBAAKBoQCz4ZqM5581jG8dIfkXMiPgYtrc5Tp3fwG2Su4l4BmOtpWaOONv\nuk6WTZZHhRKpPmCsVHHu9EVpBvyx7iXssH5j8kkq2tq2Btz957QIG3K28DA2vXJm\nFRJ0tvjmxBXqqMHKHuJI88uduPbJDJ/R5fA+aVl6dBG8zkrikkQxRGhnzcnL3PP1\nX3BIvC8FH305KvGRRPT+kBKsngzOMjtl5qErAgMBAAECgaEAmKofJfkqaSMP5pS/\nuA0I39ZmU9WEgohbJqB/b8u7RSD25RXlCR0At5WPtpFdHiBfocJlk9ziz9lrO4OX\n0kKUcjTeHi3yM0yt4Bv28m6BNHpFvrdo31jOpSkvYzcip2LdYENMTxAi4NSsDDQg\nLjuxbKJskvHgwz73XXj9g6X0uiotTzuUnT0gWJvIDykeXnoru2U2YfYjsN4uSHJF\nPWYlwQJRAOgxqQv1pe7VSQ4sLAnwW3NsGPMHCmAbmcbsjxnPj8Wjf4L0ervHxebt\nnZOCaUlUxZm9X8GiONZAGMG2xPz6tuKYz9wE/6j+9jtFe25alaCLAlEAxlLnapw5\ne3oYElrw1MR1aNOwiSXJuhQ8wlM6EifuV9HA/Aq3AApOoKmwL3n9EqfxuZbFmuRA\nu4FB78tFckIyhqhxHNz9KNZR5ZkwUdWvdeECUBLk/6GWgsM1nfVGSOsiIP76e+lC\n2GhLtq7GTzrFdiiaDmVEqbwgHI2XJmx7fz/VYyMIkwM5xTBCFQGmcs83Q6yazMdV\nrMw+uyDFna60NlrTAlBnPVkCgnjZ8mD9jSG5YNvNygUoH+e3WjmW30RnlynXxXU0\nv08sUjFEKZFx5Yr8XzjSZ85OJ2wbL9pnPeXU6OjseFsJr3CKBad0Yh5pO1evgQJR\nAMFyXCvulXFDKMqV3ePut7pMGGTUl53qoEOYGPsokl+C2Ho7sOgR2wzNLpchYZNr\nS4eCZDPgcC+1JAVOUoDK8IyPbnQaZ0K3kGWxPpzC29xj\n-----END RSA PRIVATE KEY-----\n",
          "ksk_alg": 8,
          "ksk_keytag": 61079,
          "until": "2021-03-02T10:45:48.279414Z",
          "zsk": "-----BEGIN RSA PRIVATE KEY-----\nMIICXQIBAAKBgQDQCr6AbSI9hsy6WsAzZv87brsSG1NpbYnCuZTMIrCzfB2NUF43\nRZPqTgh6dV7EtjnXeq0MsvyCbwRBRXnmQ6MlHqGtovd0k0xEzGWf3V9WLST0J8PD\nCdG7sX3gsWRkVZm6buKfmHmdgBTdWUs4ig+x7p7pwVhV0HO7x0StEEgUxwIDAQAB\nAoGANs891TPrW25SLZ6PGHvALnZDzsdoOFRlgOnHq+hPyVmfp4VO7RzllUstrKWT\nbBveLUjion/dSrfY1SFqtiGHr1w7tzTW39kTEdca4lvUtSmt7//wrEV0GLsgHwnZ\nVVyCuH0PpRcSmYYVYrSsCEH9/mXxs8Fq0tsn+wMls7O1WWECQQDruuKG/X/tYmps\nm239lLH8VyDRqQmX3mdtz+uKI8J37a+emd7lOWmkqa6b2ep+sZPDEk8xR7ktSiDb\nAhyf85jvAkEA4e5dBtUG05ieO+XtzvZOdMiU4zdWSAtgIyqegXunnvulwddEFbw0\njwRzW5MYo0eTRfgaS0obMw8uZ0hN7zPRqQJBAOH1+ZCWTNta/FLxRqTNtTMCvcXb\nuANowFIl/U0kbBQTtcVdD6lAuICL2oEwiTQ6uj5CPcEqVFoSdZ4ZzyCQG+cCQDBv\ni54FWXtPgszQlFUEVPmQburvWB4F4kxnvKeBvQPGa1jNL5mBSbtHdvuw411N4PLl\nJ63wazhdDtOxmpOnhlECQQCfdp/ZOAKUalTUuqZLgIGwobDAmcOzXN/85WWlWLIx\nDf1j0nabGCBLJt6VB0oVHd9a7rC7oTcl3TjO3kP9Zhts\n-----END RSA PRIVATE KEY-----\n",
          "zsk_alg": 8,
          "zsk_keytag": 49225
        }
      ],
      "sha": "10ea56ad7be9d3e6e75be3a15ef0dfabe9facafba486d74914e7baf8fb36638e"
    }
    """.
