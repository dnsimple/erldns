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
        {group, codec_sequential},
        {group, cache}
    ].

-spec groups() -> [ct_suite:ct_group_def()].
groups() ->
    [
        {loader, [parallel], [
            defaults,
            bad_config,
            strict_true,
            strict_false,
            strict_passes,
            one_bad_zone,
            bad_json,
            bad_json_not_list,
            valid_zones,
            load_dnssec_zone,
            wildcard_loose,
            load_zonefile,
            load_zonefile_format_auto,
            load_zonefile_rfc3597,
            load_zonefile_with_custom_decoder,
            load_zonefile_with_dnssec,
            empty_directory,
            zonefile_format_directory,
            auto_format_directory,
            error_handling_strict,
            error_handling_non_strict,
            multiple_errors,
            queued_requests,
            getter_coverage
        ]},
        {codec, [parallel], [
            json_to_erlang,
            json_to_erlang_txt_spf_records,
            json_to_erlang_ensure_sorting_and_defaults,
            json_record_to_erlang,
            json_record_soa_to_erlang,
            json_record_ns_to_erlang,
            json_record_a_to_erlang,
            json_record_aaaa_to_erlang,
            json_record_cds_to_erlang,
            json_record_tlsa_to_erlang,
            json_record_svcb_to_erlang,
            json_record_https_to_erlang,
            json_record_openpgpkey_to_erlang,
            json_record_smimea_to_erlang,
            json_record_uri_to_erlang,
            json_record_wallet_to_erlang,
            json_record_eui48_to_erlang,
            json_record_eui64_to_erlang,
            json_record_csync_to_erlang,
            json_record_dsync_to_erlang,
            json_record_zonemd_to_erlang,
            json_record_svcb_mandatory_valid,
            json_record_svcb_mandatory_self_reference,
            json_record_svcb_mandatory_missing_keys,
            json_record_https_mandatory_valid,
            json_record_svcb_no_mandatory,
            json_record_svcb_unknown_param,
            json_record_svcb_ech_param,
            json_record_svcb_ipv4hint_binary,
            json_record_svcb_ipv6hint_binary,
            json_record_svcb_no_default_alpn_atom,
            json_record_svcb_ipv4hint_invalid,
            json_record_svcb_ipv6hint_invalid,
            json_record_svcb_keynnnn_format,
            json_record_null_data,
            json_record_unsupported_type,
            json_record_context_filtered,
            encode_meta_to_json,
            encode_decode_svcb,
            encode_decode_https,
            encode_decode_openpgpkey,
            encode_decode_smimea,
            encode_decode_uri,
            encode_decode_wallet,
            encode_decode_eui48,
            encode_decode_eui64,
            encode_decode_csync,
            encode_decode_dsync,
            encode_decode_zonemd,
            parse_json_keys_unsorted_proplists_time_unit,
            parse_json_keys_unsorted_proplists
        ]},
        {codec_sequential, [], [
            custom_decode,
            encode_meta_to_json_dnssec,
            bad_custom_codecs_module_does_not_exist,
            bad_custom_codecs_module_does_not_export_callbacks
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
            put_zone_rrset_fetch_soa_match,
            put_zone_rrset_records_count_with_existing_rrset,
            put_zone_rrset_records_count_with_new_rrset,
            put_zone_rrset_records_count_matches_cache,
            put_zone_rrset_records_count_with_dnssec_zone_and_new_rrset,
            put_zone_rrset_after_soa_delete,
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
    [init_supervision_tree(Config, loader) | Config];
init_per_group(cache, Config) ->
    [init_supervision_tree(Config, cache) | Config];
init_per_group(codec, Config) ->
    [init_supervision_tree(Config, codec) | Config];
init_per_group(_, Config) ->
    Config.

-spec end_per_group(ct_suite:ct_groupname(), ct_suite:ct_config()) -> term().
end_per_group(cache, Config) ->
    application:unset_env(erldns, zones),
    Pid = proplists:get_value(cache, Config),
    ct:pal("Cache process is alive: ~p~n", [erlang:is_process_alive(Pid)]),
    exit(Pid, stop);
end_per_group(loader, Config) ->
    application:unset_env(erldns, zones),
    Pid = proplists:get_value(loader, Config),
    ct:pal("Cache process is alive: ~p~n", [erlang:is_process_alive(Pid)]),
    exit(Pid, stop);
end_per_group(codec, Config) ->
    application:unset_env(erldns, zones),
    Pid = proplists:get_value(codec, Config),
    ct:pal("Codec process is alive: ~p~n", [erlang:is_process_alive(Pid)]),
    exit(Pid, stop);
end_per_group(_, _Config) ->
    application:unset_env(erldns, zones).

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
    ZoneName = unique_name(?FUNCTION_NAME),
    Z = erldns_zone_codec:build_zone(ZoneName, ~"", [], []),
    erldns_zone_cache:put_zone(Z),
    Data = erldns_zone_codec:encode(Z, #{mode => zone_meta_to_json}),
    JSON = iolist_to_binary(json:encode(Data)),
    ?assert(is_binary(JSON)),
    Decoded = json:decode(JSON),
    ?assertMatch(
        #{
            ~"erldns" := #{
                ~"zone" := #{
                    ~"name" := ZoneName,
                    ~"version" := _,
                    ~"records_count" := 0
                }
            }
        },
        Decoded
    ).

encode_meta_to_json_dnssec(Config) ->
    DataDir = proplists:get_value(data_dir, Config),
    Path = filename:join(DataDir, "dnssec-zone.json"),
    application:set_env(erldns, zones, #{path => Path, codecs => [sample_custom_zone_codec]}),
    {ok, _} = erldns_zones:start_link(),
    LoadConfig = #{path => Path},
    ?assertMatch(1, erldns_zone_loader:load_zones(LoadConfig)),
    ZoneName = ~"example-dnssec.com",
    RecordName = ~"example-dnssec.com",
    Records = erldns_zone_cache:get_zone_records(ZoneName),
    Z = erldns_zone_codec:build_zone(ZoneName, ~"", Records, []),
    Data = erldns_zone_codec:encode(Z, #{mode => {zone_records_to_json, RecordName}}),
    JSON = iolist_to_binary(json:encode(Data)),
    ?assert(is_binary(JSON)),
    ?assertMatch(L when 8 =:= length(L), json:decode(JSON)).

json_to_erlang(_) ->
    R = erldns_zone_decoder:decode(json:decode(input()), []),
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
        }
      ],
      "sha": "10ea56ad7be9d3e6e75be3a15ef0dfabe9facafba486d74914e7baf8fb36638e"
    }
    """,
    Json = json:decode(I),
    R = erldns_zone_decoder:decode(Json, []),
    Expected = [
        #dns_rr{
            name = ~"example.com",
            type = 16,
            class = 1,
            ttl = 3600,
            data = #dns_rrdata_txt{txt = [~"this is a test"]}
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
        erldns_zone_decoder:decode(#{~"name" => ~"foo.org", ~"records" => []}, [])
    ).

json_record_to_erlang(_) ->
    ?assertEqual(not_implemented, erldns_zone_decoder:json_record_to_erlang(#{})),
    Name = ~"example.com",
    Data = #{
        ~"name" => Name, ~"type" => ~"SOA", ~"ttl" => 3600, ~"data" => null, ~"context" => null
    },
    ?assertEqual(not_implemented, erldns_zone_decoder:json_record_to_erlang(Data)).

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
        erldns_zone_decoder:json_record_to_erlang(#{
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
        erldns_zone_decoder:json_record_to_erlang(#{
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
        erldns_zone_decoder:json_record_to_erlang(#{
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
        erldns_zone_decoder:json_record_to_erlang(#{
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
        erldns_zone_decoder:json_record_to_erlang(#{
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

json_record_tlsa_to_erlang(_) ->
    Name = ~"example-dnssec.com",
    ?assertEqual(
        #dns_rr{
            name = Name,
            type = ?DNS_TYPE_TLSA,
            data =
                #dns_rrdata_tlsa{
                    usage = 3,
                    selector = 1,
                    matching_type = 1,
                    certificate = binary:decode_hex(
                        ~"DE38C1C08EB239D76B45DA575C70151CE7DA13A935BF5FB887B4E43664D6F728"
                    )
                },
            ttl = 3600
        },
        erldns_zone_decoder:json_record_to_erlang(#{
            ~"name" => Name,
            ~"type" => ~"TLSA",
            ~"ttl" => 3600,
            ~"data" => #{
                ~"usage" => 3,
                ~"selector" => 1,
                ~"matching_type" => 1,
                ~"certificate" =>
                    ~"DE38C1C08EB239D76B45DA575C70151CE7DA13A935BF5FB887B4E43664D6F728"
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
        erldns_zone_decoder:parse_keysets([
            Base#{
                ~"inception" => ~"2025-06-09T14:07:00.916361083Z",
                ~"until" => ~"2026-06-09T14:07:00.916361083Z"
            }
        ])
    ),
    %% microseconds
    ?assertMatch(
        [#keyset{inception = 1749478020, valid_until = 1781014020}],
        erldns_zone_decoder:parse_keysets([
            Base#{
                ~"inception" => ~"2025-06-09T14:07:00.916361Z",
                ~"until" => ~"2026-06-09T14:07:00.916361Z"
            }
        ])
    ),
    %% milliseconds
    ?assertMatch(
        [#keyset{inception = 1749478020, valid_until = 1781014020}],
        erldns_zone_decoder:parse_keysets([
            Base#{
                ~"inception" => ~"2025-06-09T14:07:00.916Z",
                ~"until" => ~"2026-06-09T14:07:00.916Z"
            }
        ])
    ),
    %% seconds
    ?assertMatch(
        [#keyset{inception = 1749478020, valid_until = 1781014020}],
        erldns_zone_decoder:parse_keysets([
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
        erldns_zone_decoder:parse_keysets([
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

json_record_svcb_to_erlang(_) ->
    Name = ~"example.com",
    ?assertEqual(
        #dns_rr{
            name = Name,
            type = ?DNS_TYPE_SVCB,
            data =
                #dns_rrdata_svcb{
                    svc_priority = 0,
                    target_name = ~"target.example.com",
                    svc_params = #{?DNS_SVCB_PARAM_PORT => 8080}
                },
            ttl = 3600
        },
        erldns_zone_decoder:json_record_to_erlang(#{
            ~"name" => Name,
            ~"type" => ~"SVCB",
            ~"ttl" => 3600,
            ~"data" => #{
                ~"svc_priority" => 0,
                ~"target_name" => ~"target.example.com",
                ~"svc_params" => #{~"port" => 8080}
            },
            ~"context" => null
        })
    ).

json_record_https_to_erlang(_) ->
    Name = ~"example.com",
    ?assertEqual(
        #dns_rr{
            name = Name,
            type = ?DNS_TYPE_HTTPS,
            data =
                #dns_rrdata_https{
                    svc_priority = 1,
                    target_name = ~".",
                    svc_params = #{
                        ?DNS_SVCB_PARAM_ALPN => [~"h2", ~"h3"],
                        ?DNS_SVCB_PARAM_NO_DEFAULT_ALPN => none
                    }
                },
            ttl = 3600
        },
        erldns_zone_decoder:json_record_to_erlang(#{
            ~"name" => Name,
            ~"type" => ~"HTTPS",
            ~"ttl" => 3600,
            ~"data" => #{
                ~"svc_priority" => 1,
                ~"target_name" => ~".",
                ~"svc_params" => #{
                    ~"alpn" => [~"h2", ~"h3"],
                    ~"no-default-alpn" => null
                }
            },
            ~"context" => null
        })
    ).

json_record_svcb_mandatory_valid(_) ->
    Name = ~"example.com",
    ?assertEqual(
        #dns_rr{
            name = Name,
            type = ?DNS_TYPE_SVCB,
            data =
                #dns_rrdata_svcb{
                    svc_priority = 1,
                    target_name = ~"target.example.com",
                    svc_params = #{
                        ?DNS_SVCB_PARAM_MANDATORY => [?DNS_SVCB_PARAM_PORT, ?DNS_SVCB_PARAM_ALPN],
                        ?DNS_SVCB_PARAM_PORT => 8080,
                        ?DNS_SVCB_PARAM_ALPN => [~"h2"]
                    }
                },
            ttl = 3600
        },
        erldns_zone_decoder:json_record_to_erlang(#{
            ~"name" => Name,
            ~"type" => ~"SVCB",
            ~"ttl" => 3600,
            ~"data" => #{
                ~"svc_priority" => 1,
                ~"target_name" => ~"target.example.com",
                ~"svc_params" => #{
                    ~"mandatory" => [~"port", ~"alpn"],
                    ~"port" => 8080,
                    ~"alpn" => [~"h2"]
                }
            }
        })
    ).

json_record_svcb_mandatory_self_reference(_) ->
    Name = ~"example.com",
    ?assertException(
        error,
        {svcb_mandatory_validation_error, {mandatory_self_reference, ?DNS_SVCB_PARAM_MANDATORY}},
        erldns_zone_decoder:json_record_to_erlang(#{
            ~"name" => Name,
            ~"type" => ~"SVCB",
            ~"ttl" => 3600,
            ~"data" => #{
                ~"svc_priority" => 1,
                ~"target_name" => ~"target.example.com",
                ~"svc_params" => #{
                    ~"mandatory" => [~"mandatory", ~"port"]
                }
            }
        })
    ).

json_record_svcb_mandatory_missing_keys(_) ->
    Name = ~"example.com",
    ?assertException(
        error,
        {svcb_mandatory_validation_error, {missing_mandatory_keys, [?DNS_SVCB_PARAM_PORT]}},
        erldns_zone_decoder:json_record_to_erlang(#{
            ~"name" => Name,
            ~"type" => ~"SVCB",
            ~"ttl" => 3600,
            ~"data" => #{
                ~"svc_priority" => 1,
                ~"target_name" => ~"target.example.com",
                ~"svc_params" => #{
                    ~"mandatory" => [~"port", ~"alpn"],
                    ~"alpn" => [~"h2"]
                    %% Missing port parameter
                }
            }
        })
    ).

json_record_https_mandatory_valid(_) ->
    Name = ~"example.com",
    ?assertEqual(
        #dns_rr{
            name = Name,
            type = ?DNS_TYPE_HTTPS,
            data =
                #dns_rrdata_https{
                    svc_priority = 1,
                    target_name = ~"target.example.com",
                    svc_params = #{
                        ?DNS_SVCB_PARAM_MANDATORY => [?DNS_SVCB_PARAM_IPV4HINT],
                        ?DNS_SVCB_PARAM_IPV4HINT => [{192, 0, 2, 1}]
                    }
                },
            ttl = 3600
        },
        erldns_zone_decoder:json_record_to_erlang(#{
            ~"name" => Name,
            ~"type" => ~"HTTPS",
            ~"ttl" => 3600,
            ~"data" => #{
                ~"svc_priority" => 1,
                ~"target_name" => ~"target.example.com",
                ~"svc_params" => #{
                    ~"mandatory" => [~"ipv4hint"],
                    ~"ipv4hint" => [~"192.0.2.1"]
                }
            }
        })
    ).

json_record_svcb_no_mandatory(_) ->
    Name = ~"example.com",
    ?assertEqual(
        #dns_rr{
            name = Name,
            type = ?DNS_TYPE_SVCB,
            data =
                #dns_rrdata_svcb{
                    svc_priority = 1,
                    target_name = ~"target.example.com",
                    svc_params = #{
                        ?DNS_SVCB_PARAM_PORT => 443,
                        ?DNS_SVCB_PARAM_IPV6HINT => [{16#2001, 16#db8, 0, 0, 0, 0, 0, 1}]
                    }
                },
            ttl = 3600
        },
        erldns_zone_decoder:json_record_to_erlang(#{
            ~"name" => Name,
            ~"type" => ~"SVCB",
            ~"ttl" => 3600,
            ~"data" => #{
                ~"svc_priority" => 1,
                ~"target_name" => ~"target.example.com",
                ~"svc_params" => #{
                    ~"port" => 443,
                    ~"ipv6hint" => [~"2001:db8::1"]
                }
            }
        })
    ).

json_record_svcb_unknown_param(_) ->
    Name = ~"example.com",
    ?assertEqual(
        #dns_rr{
            name = Name,
            type = ?DNS_TYPE_SVCB,
            data =
                #dns_rrdata_svcb{
                    svc_priority = 1,
                    target_name = ~"target.example.com",
                    svc_params = #{
                        ?DNS_SVCB_PARAM_PORT => 8080
                    }
                },
            ttl = 3600
        },
        erldns_zone_decoder:json_record_to_erlang(#{
            ~"name" => Name,
            ~"type" => ~"SVCB",
            ~"ttl" => 3600,
            ~"data" => #{
                ~"svc_priority" => 1,
                ~"target_name" => ~"target.example.com",
                ~"svc_params" => #{
                    ~"port" => 8080,
                    ~"unknown_param" => ~"should_be_ignored",
                    ~"another_unknown" => 123
                }
            }
        })
    ).

json_record_svcb_ech_param(_) ->
    Name = ~"example.com",
    ECHData = <<1, 2, 3, 4, 5>>,
    %% ECH parameter is stored as binary in the decoder
    ?assertEqual(
        #dns_rr{
            name = Name,
            type = ?DNS_TYPE_SVCB,
            data =
                #dns_rrdata_svcb{
                    svc_priority = 1,
                    target_name = ~"target.example.com",
                    svc_params = #{
                        ?DNS_SVCB_PARAM_ECH => ECHData
                    }
                },
            ttl = 3600
        },
        erldns_zone_decoder:json_record_to_erlang(#{
            ~"name" => Name,
            ~"type" => ~"SVCB",
            ~"ttl" => 3600,
            ~"data" => #{
                ~"svc_priority" => 1,
                ~"target_name" => ~"target.example.com",
                ~"svc_params" => #{
                    ~"ech" => ECHData
                }
            }
        })
    ).

json_record_svcb_ipv4hint_binary(_) ->
    Name = ~"example.com",
    %% Test IPv4 hint with binary IP addresses (should convert to list)
    ?assertEqual(
        #dns_rr{
            name = Name,
            type = ?DNS_TYPE_SVCB,
            data =
                #dns_rrdata_svcb{
                    svc_priority = 1,
                    target_name = ~"target.example.com",
                    svc_params = #{
                        ?DNS_SVCB_PARAM_IPV4HINT => [{192, 0, 2, 1}, {192, 0, 2, 2}]
                    }
                },
            ttl = 3600
        },
        erldns_zone_decoder:json_record_to_erlang(#{
            ~"name" => Name,
            ~"type" => ~"SVCB",
            ~"ttl" => 3600,
            ~"data" => #{
                ~"svc_priority" => 1,
                ~"target_name" => ~"target.example.com",
                ~"svc_params" => #{
                    ~"ipv4hint" => [<<"192.0.2.1">>, <<"192.0.2.2">>]
                }
            }
        })
    ).

json_record_svcb_ipv6hint_binary(_) ->
    Name = ~"example.com",
    %% Test IPv6 hint with binary IP addresses (should convert to list)
    ?assertEqual(
        #dns_rr{
            name = Name,
            type = ?DNS_TYPE_SVCB,
            data =
                #dns_rrdata_svcb{
                    svc_priority = 1,
                    target_name = ~"target.example.com",
                    svc_params = #{
                        ?DNS_SVCB_PARAM_IPV6HINT => [{16#2001, 16#db8, 0, 0, 0, 0, 0, 1}]
                    }
                },
            ttl = 3600
        },
        erldns_zone_decoder:json_record_to_erlang(#{
            ~"name" => Name,
            ~"type" => ~"SVCB",
            ~"ttl" => 3600,
            ~"data" => #{
                ~"svc_priority" => 1,
                ~"target_name" => ~"target.example.com",
                ~"svc_params" => #{
                    ~"ipv6hint" => [<<"2001:db8::1">>]
                }
            }
        })
    ).

json_record_svcb_no_default_alpn_atom(_) ->
    Name = ~"example.com",
    %% Test NO_DEFAULT_ALPN with atom 'none' (not just <<"none">>)
    ?assertEqual(
        #dns_rr{
            name = Name,
            type = ?DNS_TYPE_SVCB,
            data =
                #dns_rrdata_svcb{
                    svc_priority = 1,
                    target_name = ~"target.example.com",
                    svc_params = #{
                        ?DNS_SVCB_PARAM_NO_DEFAULT_ALPN => none
                    }
                },
            ttl = 3600
        },
        erldns_zone_decoder:json_record_to_erlang(#{
            ~"name" => Name,
            ~"type" => ~"SVCB",
            ~"ttl" => 3600,
            ~"data" => #{
                ~"svc_priority" => 1,
                ~"target_name" => ~"target.example.com",
                ~"svc_params" => #{
                    ~"no-default-alpn" => null
                }
            }
        })
    ).

json_record_svcb_ipv4hint_invalid(_) ->
    Name = ~"example.com",
    %% Test that invalid IPv4 addresses raises an error
    ?assertException(
        error,
        {invalid_ipv4_in_json, _, _},
        erldns_zone_decoder:json_record_to_erlang(#{
            ~"name" => Name,
            ~"type" => ~"SVCB",
            ~"ttl" => 3600,
            ~"data" => #{
                ~"svc_priority" => 1,
                ~"target_name" => ~"target.example.com",
                ~"svc_params" => #{
                    ~"ipv4hint" => [~"invalid.ip.address"]
                }
            }
        })
    ).

json_record_svcb_ipv6hint_invalid(_) ->
    Name = ~"example.com",
    %% Test that invalid IPv6 addresses raises an error
    ?assertException(
        error,
        {invalid_ipv6_in_json, _, _},
        erldns_zone_decoder:json_record_to_erlang(#{
            ~"name" => Name,
            ~"type" => ~"SVCB",
            ~"ttl" => 3600,
            ~"data" => #{
                ~"svc_priority" => 1,
                ~"target_name" => ~"target.example.com",
                ~"svc_params" => #{
                    ~"ipv6hint" => [~"invalid::ipv6::address"]
                }
            }
        })
    ).

json_record_svcb_keynnnn_format(_) ->
    Name = ~"example.com",
    %% Test that keyNNNN format is supported (dns_erlang supports this)
    %% Test with various keyNNNN formats: key997, key0998, key999
    Key997Value = <<"quoted">>,
    Key998Value = <<"foo">>,
    Key999Value = <<"bar">>,
    ?assertEqual(
        #dns_rr{
            name = Name,
            type = ?DNS_TYPE_SVCB,
            data =
                #dns_rrdata_svcb{
                    svc_priority = 6,
                    target_name = ~".",
                    svc_params = #{
                        997 => Key997Value,
                        998 => Key998Value,
                        999 => Key999Value
                    }
                },
            ttl = 120
        },
        erldns_zone_decoder:json_record_to_erlang(#{
            ~"name" => Name,
            ~"type" => ~"SVCB",
            ~"ttl" => 120,
            ~"data" => #{
                ~"svc_priority" => 6,
                ~"target_name" => ~".",
                ~"svc_params" => #{
                    ~"key997" => Key997Value,
                    ~"key0998" => Key998Value,
                    ~"key999" => Key999Value
                }
            }
        })
    ),
    %% Test that keyNNNN format works in mandatory parameter list
    ?assertEqual(
        #dns_rr{
            name = Name,
            type = ?DNS_TYPE_SVCB,
            data =
                #dns_rrdata_svcb{
                    svc_priority = 1,
                    target_name = ~"target.example.com",
                    svc_params = #{
                        ?DNS_SVCB_PARAM_MANDATORY => [997, 998],
                        997 => Key997Value,
                        998 => Key998Value
                    }
                },
            ttl = 3600
        },
        erldns_zone_decoder:json_record_to_erlang(#{
            ~"name" => Name,
            ~"type" => ~"SVCB",
            ~"ttl" => 3600,
            ~"data" => #{
                ~"svc_priority" => 1,
                ~"target_name" => ~"target.example.com",
                ~"svc_params" => #{
                    ~"mandatory" => [~"key997", ~"key0998"],
                    ~"key997" => Key997Value,
                    ~"key0998" => Key998Value
                }
            }
        })
    ).

json_record_null_data(_) ->
    %% Test that records with null data return not_implemented
    ?assertEqual(
        not_implemented,
        erldns_zone_decoder:json_record_to_erlang(#{
            ~"name" => ~"example.com",
            ~"type" => ~"A",
            ~"ttl" => 3600,
            ~"data" => null
        })
    ).

json_record_unsupported_type(_) ->
    %% Test that unsupported record types return not_implemented
    ?assertEqual(
        not_implemented,
        erldns_zone_decoder:decode_record(
            #{
                ~"name" => ~"example.com",
                ~"type" => ~"UNKNOWN_TYPE",
                ~"ttl" => 3600,
                ~"data" => #{}
            },
            []
        )
    ).

json_record_context_filtered(_) ->
    %% Test that records are filtered by context options
    application:set_env(erldns, zones, #{
        context_options => #{
            match_empty => false,
            allow => [~"production"]
        }
    }),
    try
        %% Record with empty context should be filtered out
        ?assertEqual(
            not_implemented,
            erldns_zone_decoder:decode_record(
                #{
                    ~"name" => ~"example.com",
                    ~"type" => ~"A",
                    ~"ttl" => 3600,
                    ~"data" => #{~"ip" => ~"192.0.2.1"},
                    ~"context" => []
                },
                []
            )
        ),
        %% Record with matching context should pass
        ?assertEqual(
            #dns_rr{
                name = ~"example.com",
                type = ?DNS_TYPE_A,
                data = #dns_rrdata_a{ip = {192, 0, 2, 1}},
                ttl = 3600
            },
            erldns_zone_decoder:decode_record(
                #{
                    ~"name" => ~"example.com",
                    ~"type" => ~"A",
                    ~"ttl" => 3600,
                    ~"data" => #{~"ip" => ~"192.0.2.1"},
                    ~"context" => [~"production"]
                },
                []
            )
        )
    after
        application:unset_env(erldns, zones)
    end.

json_record_openpgpkey_to_erlang(_) ->
    Name = ~"_openpgpkey.example.com",
    PgpData = base64:encode(<<1, 2, 3, 4, 5>>),
    ?assertEqual(
        #dns_rr{
            name = Name,
            type = ?DNS_TYPE_OPENPGPKEY,
            data = #dns_rrdata_openpgpkey{data = <<1, 2, 3, 4, 5>>},
            ttl = 3600
        },
        erldns_zone_decoder:json_record_to_erlang(#{
            ~"name" => Name,
            ~"type" => ~"OPENPGPKEY",
            ~"ttl" => 3600,
            ~"data" => #{~"data" => PgpData},
            ~"context" => null
        })
    ),
    %% Negative case: invalid base64 data
    ?assertEqual(
        not_implemented,
        erldns_zone_decoder:json_record_to_erlang(#{
            ~"name" => Name,
            ~"type" => ~"OPENPGPKEY",
            ~"ttl" => 3600,
            ~"data" => #{~"data" => <<"invalid_base64!!!">>},
            ~"context" => null
        })
    ).

json_record_smimea_to_erlang(_) ->
    Name = ~"_smimecert.example.com",
    ?assertEqual(
        #dns_rr{
            name = Name,
            type = ?DNS_TYPE_SMIMEA,
            data =
                #dns_rrdata_smimea{
                    usage = 3,
                    selector = 1,
                    matching_type = 1,
                    certificate = binary:decode_hex(
                        ~"DE38C1C08EB239D76B45DA575C70151CE7DA13A935BF5FB887B4E43664D6F728"
                    )
                },
            ttl = 3600
        },
        erldns_zone_decoder:json_record_to_erlang(#{
            ~"name" => Name,
            ~"type" => ~"SMIMEA",
            ~"ttl" => 3600,
            ~"data" => #{
                ~"usage" => 3,
                ~"selector" => 1,
                ~"matching_type" => 1,
                ~"certificate" =>
                    ~"DE38C1C08EB239D76B45DA575C70151CE7DA13A935BF5FB887B4E43664D6F728"
            },
            ~"context" => null
        })
    ),
    %% Negative case: invalid base64 data
    ?assertEqual(
        not_implemented,
        erldns_zone_decoder:json_record_to_erlang(#{
            ~"name" => Name,
            ~"type" => ~"OPENPGPKEY",
            ~"ttl" => 3600,
            ~"data" => #{~"data" => <<"invalid_base64!!!">>},
            ~"context" => null
        })
    ),
    %% Negative case: invalid hex data (odd number of characters)
    ?assertEqual(
        not_implemented,
        erldns_zone_decoder:json_record_to_erlang(#{
            ~"name" => Name,
            ~"type" => ~"SMIMEA",
            ~"ttl" => 3600,
            ~"data" => #{
                ~"usage" => 3,
                ~"selector" => 1,
                ~"matching_type" => 1,
                ~"certificate" => ~"DE38C1C08EB239D76B45DA575C70151CE7DA13A935BF5FB887B4E43664D6F72"
            },
            ~"context" => null
        })
    ),
    %% Negative case: invalid hex characters
    ?assertEqual(
        not_implemented,
        erldns_zone_decoder:json_record_to_erlang(#{
            ~"name" => Name,
            ~"type" => ~"SMIMEA",
            ~"ttl" => 3600,
            ~"data" => #{
                ~"usage" => 3,
                ~"selector" => 1,
                ~"matching_type" => 1,
                ~"certificate" => ~"INVALID_HEX_DATA!!!"
            },
            ~"context" => null
        })
    ).

json_record_uri_to_erlang(_) ->
    Name = ~"example.com",
    ?assertEqual(
        #dns_rr{
            name = Name,
            type = ?DNS_TYPE_URI,
            data =
                #dns_rrdata_uri{
                    priority = 10,
                    weight = 5,
                    target = ~"https://example.com/path"
                },
            ttl = 3600
        },
        erldns_zone_decoder:json_record_to_erlang(#{
            ~"name" => Name,
            ~"type" => ~"URI",
            ~"ttl" => 3600,
            ~"data" => #{
                ~"priority" => 10,
                ~"weight" => 5,
                ~"target" => ~"https://example.com/path"
            },
            ~"context" => null
        })
    ).

json_record_wallet_to_erlang(_) ->
    Name = ~"example.com",
    WalletData = base64:encode(<<1, 2, 3, 4, 5>>),
    ?assertEqual(
        #dns_rr{
            name = Name,
            type = ?DNS_TYPE_WALLET,
            data = #dns_rrdata_wallet{data = <<1, 2, 3, 4, 5>>},
            ttl = 3600
        },
        erldns_zone_decoder:json_record_to_erlang(#{
            ~"name" => Name,
            ~"type" => ~"WALLET",
            ~"ttl" => 3600,
            ~"data" => #{~"data" => WalletData},
            ~"context" => null
        })
    ),
    %% Negative case: invalid base64 data
    ?assertEqual(
        not_implemented,
        erldns_zone_decoder:json_record_to_erlang(#{
            ~"name" => Name,
            ~"type" => ~"WALLET",
            ~"ttl" => 3600,
            ~"data" => #{~"data" => <<"invalid_base64!!!">>},
            ~"context" => null
        })
    ).

json_record_eui48_to_erlang(_) ->
    Name = ~"example.com",
    AddressHex = ~"001122334455",
    ?assertEqual(
        #dns_rr{
            name = Name,
            type = ?DNS_TYPE_EUI48,
            data = #dns_rrdata_eui48{address = <<0, 17, 34, 51, 68, 85>>},
            ttl = 3600
        },
        erldns_zone_decoder:json_record_to_erlang(#{
            ~"name" => Name,
            ~"type" => ~"EUI48",
            ~"ttl" => 3600,
            ~"data" => #{~"address" => AddressHex},
            ~"context" => null
        })
    ),
    %% Negative case: invalid hex (wrong length - not 12 hex chars = 6 bytes)
    ?assertEqual(
        not_implemented,
        erldns_zone_decoder:json_record_to_erlang(#{
            ~"name" => Name,
            ~"type" => ~"EUI48",
            ~"ttl" => 3600,
            %% 11 chars instead of 12
            ~"data" => #{~"address" => ~"00112233445"},
            ~"context" => null
        })
    ),
    %% Negative case: invalid hex characters
    ?assertEqual(
        not_implemented,
        erldns_zone_decoder:json_record_to_erlang(#{
            ~"name" => Name,
            ~"type" => ~"EUI48",
            ~"ttl" => 3600,
            ~"data" => #{~"address" => ~"INVALID_HEX"},
            ~"context" => null
        })
    ).

json_record_eui64_to_erlang(_) ->
    Name = ~"example.com",
    AddressHex = ~"0011223344556677",
    ?assertEqual(
        #dns_rr{
            name = Name,
            type = ?DNS_TYPE_EUI64,
            data = #dns_rrdata_eui64{address = <<0, 17, 34, 51, 68, 85, 102, 119>>},
            ttl = 3600
        },
        erldns_zone_decoder:json_record_to_erlang(#{
            ~"name" => Name,
            ~"type" => ~"EUI64",
            ~"ttl" => 3600,
            ~"data" => #{~"address" => AddressHex},
            ~"context" => null
        })
    ),
    %% Negative case: invalid hex (wrong length - not 16 hex chars = 8 bytes)
    ?assertEqual(
        not_implemented,
        erldns_zone_decoder:json_record_to_erlang(#{
            ~"name" => Name,
            ~"type" => ~"EUI64",
            ~"ttl" => 3600,
            %% 15 chars instead of 16
            ~"data" => #{~"address" => ~"001122334455667"},
            ~"context" => null
        })
    ),
    %% Negative case: invalid hex characters
    ?assertEqual(
        not_implemented,
        erldns_zone_decoder:json_record_to_erlang(#{
            ~"name" => Name,
            ~"type" => ~"EUI64",
            ~"ttl" => 3600,
            ~"data" => #{~"address" => ~"INVALID_HEX_DATA"},
            ~"context" => null
        })
    ).

json_record_csync_to_erlang(_) ->
    Name = ~"example.com",
    ?assertEqual(
        #dns_rr{
            name = Name,
            type = ?DNS_TYPE_CSYNC,
            data =
                #dns_rrdata_csync{
                    soa_serial = 12345,
                    flags = 0,
                    types = [1, 2, 28]
                },
            ttl = 3600
        },
        erldns_zone_decoder:json_record_to_erlang(#{
            ~"name" => Name,
            ~"type" => ~"CSYNC",
            ~"ttl" => 3600,
            ~"data" => #{
                ~"soa_serial" => 12345,
                ~"flags" => 0,
                ~"types" => [1, 2, 28]
            },
            ~"context" => null
        })
    ).

json_record_dsync_to_erlang(_) ->
    Name = ~"example.com",
    ?assertEqual(
        #dns_rr{
            name = Name,
            type = ?DNS_TYPE_DSYNC,
            data =
                #dns_rrdata_dsync{
                    rrtype = 1,
                    scheme = 1,
                    port = 443,
                    target = ~"target.example.com"
                },
            ttl = 3600
        },
        erldns_zone_decoder:json_record_to_erlang(#{
            ~"name" => Name,
            ~"type" => ~"DSYNC",
            ~"ttl" => 3600,
            ~"data" => #{
                ~"rrtype" => 1,
                ~"scheme" => 1,
                ~"port" => 443,
                ~"target" => ~"target.example.com"
            },
            ~"context" => null
        })
    ).

json_record_zonemd_to_erlang(_) ->
    Name = ~"example.com",
    % SHA384 produces 48 bytes (96 hex chars) - using correct hash from dns_erlang test
    HashHex =
        <<"F8857A5A89EF49FFC2EBE05F2718735EE574AC9FE68F473083F0F54BFA39C81801E4367FEFF3DEA0C14F57283A7C66AD">>,
    ?assertEqual(
        #dns_rr{
            name = Name,
            type = ?DNS_TYPE_ZONEMD,
            data =
                #dns_rrdata_zonemd{
                    serial = 2025121100,
                    scheme = 1,
                    algorithm = ?DNS_ZONEMD_ALG_SHA384,
                    hash = binary:decode_hex(HashHex)
                },
            ttl = 3600
        },
        erldns_zone_decoder:json_record_to_erlang(#{
            ~"name" => Name,
            ~"type" => ~"ZONEMD",
            ~"ttl" => 3600,
            ~"data" => #{
                ~"serial" => 2025121100,
                ~"scheme" => 1,
                ~"algorithm" => ?DNS_ZONEMD_ALG_SHA384,
                ~"hash" => HashHex
            },
            ~"context" => null
        })
    ),
    %% Negative case: invalid hex (odd number of characters)
    ?assertEqual(
        not_implemented,
        erldns_zone_decoder:json_record_to_erlang(#{
            ~"name" => Name,
            ~"type" => ~"ZONEMD",
            ~"ttl" => 3600,
            ~"data" => #{
                ~"serial" => 2025121100,
                ~"scheme" => 1,
                ~"algorithm" => ?DNS_ZONEMD_ALG_SHA384,
                ~"hash" =>
                    <<"F8857A5A89EF49FFC2EBE05F2718735EE574AC9FE68F473083F0F54BFA39C81801E4367FEFF3DEA0C14F57283A7C66A">>
            },
            ~"context" => null
        })
    ),
    %% Negative case: invalid hex characters
    ?assertEqual(
        not_implemented,
        erldns_zone_decoder:json_record_to_erlang(#{
            ~"name" => Name,
            ~"type" => ~"ZONEMD",
            ~"ttl" => 3600,
            ~"data" => #{
                ~"serial" => 2025121100,
                ~"scheme" => 1,
                ~"algorithm" => ?DNS_ZONEMD_ALG_SHA384,
                ~"hash" => <<"INVALID_HEX_DATA!!!">>
            },
            ~"context" => null
        })
    ).

encode_decode_svcb(_) ->
    Name = unique_name(?FUNCTION_NAME),
    Record = #dns_rr{
        name = Name,
        type = ?DNS_TYPE_SVCB,
        data =
            #dns_rrdata_svcb{
                svc_priority = 0,
                target_name = <<"target.", Name/binary>>,
                svc_params = #{}
            },
        ttl = 120
    },
    RecordWithParams = #dns_rr{
        name = Name,
        type = ?DNS_TYPE_SVCB,
        data =
            #dns_rrdata_svcb{
                svc_priority = 1,
                target_name = <<"target.", Name/binary>>,
                svc_params = #{
                    ?DNS_SVCB_PARAM_PORT => 8080,
                    3232 => ~"custom\"text"
                }
            },
        ttl = 3600
    },
    Zone = erldns_zone_codec:build_zone(Name, ~"ver", [Record, RecordWithParams], []),
    erldns_zone_cache:put_zone(Zone),
    Encoded = erldns_zone_codec:encode(Zone, #{mode => zone_records_to_json}),
    ?assertMatch([_, _], Encoded),
    [EncodedRecord, EncodedRecordWithParams] = lists:sort(Encoded),
    ?assertMatch(#{~"type" := ~"SVCB", ~"name" := _, ~"ttl" := 120}, EncodedRecord),
    ?assertMatch(#{~"type" := ~"SVCB", ~"name" := _, ~"ttl" := 3600}, EncodedRecordWithParams),
    Content = maps:get(~"content", EncodedRecordWithParams),
    ?assertNotMatch(
        nomatch, string:find(Content, ~"port=\"8080\" key3232=\"custom\\\"text"), Content
    ).

encode_decode_https(_) ->
    Name = unique_name(?FUNCTION_NAME),
    Record = #dns_rr{
        name = Name,
        type = ?DNS_TYPE_HTTPS,
        data =
            #dns_rrdata_https{
                svc_priority = 0,
                target_name = ~".",
                svc_params = #{}
            },
        ttl = 3600
    },
    RecordWithParams = #dns_rr{
        name = Name,
        type = ?DNS_TYPE_HTTPS,
        data =
            #dns_rrdata_https{
                svc_priority = 1,
                target_name = ~".",
                svc_params = #{?DNS_SVCB_PARAM_ALPN => [~"h2", ~"h3"]}
            },
        ttl = 3600
    },
    Zone = erldns_zone_codec:build_zone(Name, ~"ver", [Record, RecordWithParams], []),
    erldns_zone_cache:put_zone(Zone),
    Encoded = erldns_zone_codec:encode(Zone, #{mode => zone_records_to_json}),
    ?assertMatch([_, _], Encoded),
    [EncodedRecord, EncodedRecordWithParams] = lists:sort(Encoded),
    ?assertMatch(#{~"type" := ~"HTTPS", ~"name" := _, ~"ttl" := 3600}, EncodedRecord),
    ?assertMatch(#{~"type" := ~"HTTPS", ~"name" := _, ~"ttl" := 3600}, EncodedRecordWithParams).

encode_decode_openpgpkey(_) ->
    PidStr = pid_to_list(self()),
    UniqueId = erlang:phash2(PidStr),
    Name = erlang:iolist_to_binary([
        ~"_openpgpkey.encode-decode-openpgpkey-", integer_to_binary(UniqueId), ~".com"
    ]),
    Record = #dns_rr{
        name = Name,
        type = ?DNS_TYPE_OPENPGPKEY,
        data = #dns_rrdata_openpgpkey{data = <<1, 2, 3, 4, 5>>},
        ttl = 3600
    },
    Zone = erldns_zone_codec:build_zone(Name, ~"", [Record], []),
    erldns_zone_cache:put_zone(Zone),
    Encoded = erldns_zone_codec:encode(Zone, #{mode => zone_records_to_json}),
    ?assertMatch([_], Encoded),
    [EncodedRecord] = Encoded,
    ?assertMatch(#{~"type" := ~"OPENPGPKEY", ~"name" := _, ~"ttl" := 3600}, EncodedRecord).

encode_decode_smimea(_) ->
    PidStr = pid_to_list(self()),
    UniqueId = erlang:phash2(PidStr),
    Name = erlang:iolist_to_binary([
        ~"_smimecert.encode-decode-smimea-", integer_to_binary(UniqueId), ~".com"
    ]),
    Record = #dns_rr{
        name = Name,
        type = ?DNS_TYPE_SMIMEA,
        data =
            #dns_rrdata_smimea{
                usage = 3,
                selector = 1,
                matching_type = 1,
                certificate = binary:decode_hex(
                    ~"DE38C1C08EB239D76B45DA575C70151CE7DA13A935BF5FB887B4E43664D6F728"
                )
            },
        ttl = 3600
    },
    Zone = erldns_zone_codec:build_zone(Name, ~"", [Record], []),
    erldns_zone_cache:put_zone(Zone),
    Encoded = erldns_zone_codec:encode(Zone, #{mode => zone_records_to_json}),
    ?assertMatch([_], Encoded),
    [EncodedRecord] = Encoded,
    ?assertMatch(#{~"type" := ~"SMIMEA", ~"name" := _, ~"ttl" := 3600}, EncodedRecord).

encode_decode_uri(_) ->
    Name = unique_name(?FUNCTION_NAME),
    Record = #dns_rr{
        name = Name,
        type = ?DNS_TYPE_URI,
        data =
            #dns_rrdata_uri{
                priority = 10,
                weight = 5,
                target = ~"https://example.com/path"
            },
        ttl = 3600
    },
    Zone = erldns_zone_codec:build_zone(Name, ~"", [Record], []),
    erldns_zone_cache:put_zone(Zone),
    Encoded = erldns_zone_codec:encode(Zone, #{mode => zone_records_to_json}),
    ?assertMatch([_], Encoded),
    [EncodedRecord] = Encoded,
    ?assertMatch(#{~"type" := ~"URI", ~"name" := _, ~"ttl" := 3600}, EncodedRecord).

encode_decode_wallet(_) ->
    Name = unique_name(?FUNCTION_NAME),
    Record = #dns_rr{
        name = Name,
        type = ?DNS_TYPE_WALLET,
        data = #dns_rrdata_wallet{data = <<1, 2, 3, 4, 5>>},
        ttl = 3600
    },
    Zone = erldns_zone_codec:build_zone(Name, ~"", [Record], []),
    erldns_zone_cache:put_zone(Zone),
    Encoded = erldns_zone_codec:encode(Zone, #{mode => zone_records_to_json}),
    ?assertMatch([_], Encoded),
    [EncodedRecord] = Encoded,
    ?assertMatch(#{~"type" := ~"WALLET", ~"name" := _, ~"ttl" := 3600}, EncodedRecord).

encode_decode_eui48(_) ->
    Name = unique_name(?FUNCTION_NAME),
    Record = #dns_rr{
        name = Name,
        type = ?DNS_TYPE_EUI48,
        data = #dns_rrdata_eui48{address = <<0, 17, 34, 51, 68, 85>>},
        ttl = 3600
    },
    Zone = erldns_zone_codec:build_zone(Name, ~"", [Record], []),
    erldns_zone_cache:put_zone(Zone),
    Encoded = erldns_zone_codec:encode(Zone, #{mode => zone_records_to_json}),
    ?assertMatch([_], Encoded),
    [EncodedRecord] = Encoded,
    ?assertMatch(#{~"type" := ~"EUI48", ~"name" := _, ~"ttl" := 3600}, EncodedRecord).

encode_decode_eui64(_) ->
    Name = unique_name(?FUNCTION_NAME),
    Record = #dns_rr{
        name = Name,
        type = ?DNS_TYPE_EUI64,
        data = #dns_rrdata_eui64{address = <<0, 17, 34, 51, 68, 85, 102, 119>>},
        ttl = 3600
    },
    Zone = erldns_zone_codec:build_zone(Name, ~"", [Record], []),
    erldns_zone_cache:put_zone(Zone),
    Encoded = erldns_zone_codec:encode(Zone, #{mode => zone_records_to_json}),
    ?assertMatch([_], Encoded),
    [EncodedRecord] = Encoded,
    ?assertMatch(#{~"type" := ~"EUI64", ~"name" := _, ~"ttl" := 3600}, EncodedRecord).

encode_decode_csync(_) ->
    Name = unique_name(?FUNCTION_NAME),
    Record = #dns_rr{
        name = Name,
        type = ?DNS_TYPE_CSYNC,
        data =
            #dns_rrdata_csync{
                soa_serial = 12345,
                flags = 0,
                types = [1, 2, 28]
            },
        ttl = 3600
    },
    Zone = erldns_zone_codec:build_zone(Name, ~"", [Record], []),
    erldns_zone_cache:put_zone(Zone),
    Encoded = erldns_zone_codec:encode(Zone, #{mode => zone_records_to_json}),
    ?assertMatch([_], Encoded),
    [EncodedRecord] = Encoded,
    ?assertMatch(#{~"type" := ~"CSYNC", ~"name" := _, ~"ttl" := 3600}, EncodedRecord).

encode_decode_dsync(_) ->
    Name = unique_name(?FUNCTION_NAME),
    Record = #dns_rr{
        name = Name,
        type = ?DNS_TYPE_DSYNC,
        data =
            #dns_rrdata_dsync{
                rrtype = 1,
                scheme = 1,
                port = 443,
                target = ~"target.example.com"
            },
        ttl = 3600
    },
    Zone = erldns_zone_codec:build_zone(Name, ~"", [Record], []),
    erldns_zone_cache:put_zone(Zone),
    Encoded = erldns_zone_codec:encode(Zone, #{mode => zone_records_to_json}),
    ?assertMatch([_], Encoded),
    [EncodedRecord] = Encoded,
    ?assertMatch(#{~"type" := ~"DSYNC", ~"name" := _, ~"ttl" := 3600}, EncodedRecord).

encode_decode_zonemd(_) ->
    Name = unique_name(?FUNCTION_NAME),
    % SHA384 produces 48 bytes (96 hex chars) - using correct hash from dns_erlang test
    HashHex =
        <<"F8857A5A89EF49FFC2EBE05F2718735EE574AC9FE68F473083F0F54BFA39C81801E4367FEFF3DEA0C14F57283A7C66AD">>,
    Hash = binary:decode_hex(HashHex),
    Record = #dns_rr{
        name = Name,
        type = ?DNS_TYPE_ZONEMD,
        data =
            #dns_rrdata_zonemd{
                serial = 2025121100,
                scheme = 1,
                algorithm = ?DNS_ZONEMD_ALG_SHA384,
                hash = Hash
            },
        ttl = 3600
    },
    Zone = erldns_zone_codec:build_zone(Name, ~"", [Record], []),
    erldns_zone_cache:put_zone(Zone),
    Encoded = erldns_zone_codec:encode(Zone, #{mode => zone_records_to_json}),
    ?assertMatch([_], Encoded),
    [EncodedRecord] = Encoded,
    ?assertMatch(#{~"type" := ~"ZONEMD", ~"name" := _, ~"ttl" := 3600}, EncodedRecord).

defaults(_) ->
    ?assertMatch(0, erldns_zone_loader:load_zones()).

bad_config(_) ->
    LoadConfig = #{strict => very_invalid},
    ?assertError({badconfig, _}, erldns_zone_loader:load_zones(LoadConfig)).

strict_true(_) ->
    LoadConfig = #{strict => true},
    ?assertError({badconfig, enoent}, erldns_zone_loader:load_zones(LoadConfig)).

strict_false(_) ->
    LoadConfig = #{strict => false},
    ?assertMatch(0, erldns_zone_loader:load_zones(LoadConfig)).

strict_passes(Config) ->
    DataDir = proplists:get_value(data_dir, Config),
    Path = filename:join(DataDir, "good.json"),
    LoadConfig = #{path => Path},
    ?assertMatch(0, erldns_zone_loader:load_zones(LoadConfig)).

one_bad_zone(Config) ->
    DataDir = proplists:get_value(data_dir, Config),
    LoadConfig = #{path => DataDir},
    ?assertError(_, erldns_zone_loader:load_zones(LoadConfig)).

bad_json(Config) ->
    DataDir = proplists:get_value(data_dir, Config),
    Path = filename:join(DataDir, "bad_json.json"),
    LoadConfig = #{path => Path},
    ?assertError([{json_error, _}], erldns_zone_loader:load_zones(LoadConfig)).

bad_json_not_list(Config) ->
    DataDir = proplists:get_value(data_dir, Config),
    Path = filename:join(DataDir, "json_not_list.json"),
    LoadConfig = #{path => Path},
    ?assertError([{invalid_zone_file, _}], erldns_zone_loader:load_zones(LoadConfig)).

valid_zones(Config) ->
    DataDir = proplists:get_value(data_dir, Config),
    Path = filename:join(DataDir, "standard.json"),
    LoadConfig = #{path => Path},
    ?assertMatch(1, erldns_zone_loader:load_zones(LoadConfig)).

load_dnssec_zone(Config) ->
    DataDir = proplists:get_value(data_dir, Config),
    Path = filename:join(DataDir, "dnssec-zone.json"),
    LoadConfig = #{path => Path, strict => true},
    ?assertMatch(1, erldns_zone_loader:load_zones(LoadConfig)).

wildcard_loose(Config) ->
    DataDir = proplists:get_value(data_dir, Config),
    LoadConfig = #{strict => false, path => DataDir},
    ?assertMatch(3, erldns_zone_loader:load_zones(LoadConfig)).

load_zonefile(Config) ->
    DataDir = proplists:get_value(data_dir, Config),
    Path = filename:join(DataDir, "example.zone"),
    LoadConfig = #{path => Path, format => zonefile},
    ?assertMatch(1, erldns_zone_loader:load_zones(LoadConfig)).

load_zonefile_format_auto(Config) ->
    DataDir = proplists:get_value(data_dir, Config),
    % Test auto-detection with .zone extension
    Path = filename:join(DataDir, "example.zone"),
    LoadConfig1 = #{path => Path, format => auto},
    ?assertMatch(1, erldns_zone_loader:load_zones(LoadConfig1)),
    % Test auto-detection with .json extension
    JsonPath = filename:join(DataDir, "standard.json"),
    LoadConfig2 = #{path => JsonPath, format => auto},
    ?assertMatch(1, erldns_zone_loader:load_zones(LoadConfig2)).

load_zonefile_rfc3597(Config) ->
    DataDir = proplists:get_value(data_dir, Config),
    Path = filename:join(DataDir, "rfc3597.zone"),
    LoadConfig = #{path => Path, format => zonefile, strict => false},
    ?assertMatch(1, erldns_zone_loader:load_zones(LoadConfig)).

load_zonefile_with_custom_decoder(Config) ->
    DataDir = proplists:get_value(data_dir, Config),
    Path = filename:join(DataDir, "rfc3597.zone"),
    LoadConfig = #{path => Path, format => zonefile},
    Result = erldns_zone_loader:load_zones(LoadConfig),
    ?assertMatch(1, Result),
    Records = erldns_zone_cache:get_zone_records(~"example-rfc3597.com"),
    ?assert(lists:any(fun(#dns_rr{data = Data}) -> ~"example.net" =:= Data end, Records)).

load_zonefile_with_dnssec(Config) ->
    DataDir = proplists:get_value(data_dir, Config),
    Path = filename:join(DataDir, "dnssec.zone"),
    LoadConfig = #{path => Path, keys_path => DataDir, format => zonefile},
    Result = erldns_zone_loader:load_zones(LoadConfig),
    ?assertMatch(1, Result),
    Zone = erldns_zone_cache:lookup_zone(~"a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11.com"),
    ?assertMatch([_ | _], Zone#zone.keysets).

empty_directory(Config) ->
    PrivDir = proplists:get_value(priv_dir, Config),
    EmptyDir = filename:join(PrivDir, "empty_dir"),
    ok = filelib:ensure_dir(filename:join(EmptyDir, "dummy")),
    LoadConfig = #{path => EmptyDir, strict => false},
    Result = erldns_zone_loader:load_zones(LoadConfig),
    ?assertMatch(0, Result).

zonefile_format_directory(Config) ->
    DataDir = proplists:get_value(data_dir, Config),
    LoadConfig = #{path => DataDir, format => zonefile, strict => false},
    Result = erldns_zone_loader:load_zones(LoadConfig),
    % Should find at least example.zone, rfc3597.zone
    ?assertMatch(N when N >= 2, Result).

auto_format_directory(Config) ->
    % Test auto format with directory - should find both .json and .zone files
    DataDir = proplists:get_value(data_dir, Config),
    LoadConfig = #{path => DataDir, format => auto, strict => false},
    Result = erldns_zone_loader:load_zones(LoadConfig),
    % Should find multiple files (both json and zone)
    ?assertMatch(N when N >= 3, Result).

error_handling_strict(Config) ->
    % Test error handling in strict mode - should return error
    DataDir = proplists:get_value(data_dir, Config),
    BadPath = filename:join(DataDir, "nonexistent.json"),
    LoadConfig = #{path => BadPath, strict => true},
    ?assertError({badconfig, _}, erldns_zone_loader:load_zones(LoadConfig)).

error_handling_non_strict(Config) ->
    % Test error handling in non-strict mode - should return count (0) even with errors
    % This tests lines 169-175 (non-strict error handling path)
    PrivDir = proplists:get_value(priv_dir, Config),
    % Create a directory with an invalid file
    TestDir = filename:join(PrivDir, "non_strict_error_test"),
    ok = filelib:ensure_dir(filename:join(TestDir, "dummy")),
    InvalidFile = filename:join(TestDir, "invalid.json"),
    ok = file:write_file(InvalidFile, ~"{invalid json"),
    LoadConfig = #{path => TestDir, format => json, strict => false},
    Result = erldns_zone_loader:load_zones(LoadConfig),
    % In non-strict mode, should return 0 instead of error
    ?assertMatch(0, Result).

multiple_errors(Config) ->
    % Test multiple error handling - second error should preserve first error
    % This tests the case where CurrentError is already set (line 153)
    % and the "still waiting for more replies" path (lines 187-190)
    PrivDir = proplists:get_value(priv_dir, Config),
    % Create a directory with multiple invalid files to trigger multiple errors
    TestDir = filename:join(PrivDir, "multi_error_test"),
    ok = filelib:ensure_dir(filename:join(TestDir, "dummy")),
    % Create multiple invalid JSON files - this will cause parallel processing
    % where multiple workers fail, testing the error accumulation logic
    InvalidFile1 = filename:join(TestDir, "invalid1.json"),
    InvalidFile2 = filename:join(TestDir, "invalid2.json"),
    ok = file:write_file(InvalidFile1, ~"{invalid json 1"),
    ok = file:write_file(InvalidFile2, ~"{invalid json 2"),
    LoadConfig = #{path => TestDir, format => json, strict => true},
    ?assertError([{json_error, _}, {json_error, _}], erldns_zone_loader:load_zones(LoadConfig)).

queued_requests(Config) ->
    erlang:process_flag(trap_exit, true),
    % Test queuing behavior when a request is already running
    % This tests lines 217-219 (queuing when running_call is not undefined)
    DataDir = proplists:get_value(data_dir, Config),
    Path = filename:join(DataDir, "standard.json"),
    LoadConfig = #{path => Path, strict => false},
    % Start first request in a separate process
    Self = self(),
    Ref1 = make_ref(),
    Ref2 = make_ref(),
    spawn_link(fun() ->
        Result1 = erldns_zone_loader:load_zones(LoadConfig),
        Self ! {Ref1, Result1}
    end),
    % Start second request immediately (should be queued)
    spawn_link(fun() ->
        Result2 = erldns_zone_loader:load_zones(LoadConfig),
        Self ! {Ref2, Result2}
    end),
    % Wait for both results
    receive
        {Ref1, R1} ->
            ?assertMatch(1, R1),
            ok
    after 10000 -> ct:fail("First request timed out")
    end,
    receive
        {Ref2, R2} ->
            ?assertMatch(1, R2),
            ok
    after 10000 -> ct:fail("Second request timed out")
    end.

% Test handling of unexpected gen_server calls
getter_coverage(_) ->
    Result = gen_server:call(erldns_zone_loader_getter, unexpected_message),
    ?assertMatch({error, not_implemented}, Result),
    gen_server:cast(erldns_zone_loader_getter, unexpected_message),
    timer:sleep(100),
    ?assert(erlang:is_process_alive(whereis(erldns_zone_loader_getter))).

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
    NxName = dns_domain:to_lower(~"nxname.a1.example.net"),
    NxName2 = dns_domain:to_lower(~"nxname.a1.example.com"),
    Name = dns_domain:to_lower(~"a1.example.com"),
    Labels = dns_domain:split(dns_domain:to_lower(~"a1.example.com")),
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
    NxName = dns_domain:to_lower(~"nxname.a1.example.net"),
    Name = dns_domain:to_lower(~"a1.example.com"),
    Labels = dns_domain:split(dns_domain:to_lower(~"a1.example.com")),
    Zone = erldns_zone_cache:lookup_zone(~"example.com"),
    ?assertMatch([], erldns_zone_cache:get_records_by_name_and_type(NxName, Type)),
    ?assertMatch([#dns_rr{}], erldns_zone_cache:get_records_by_name_and_type(Labels, Type)),
    ?assertMatch([#dns_rr{}], erldns_zone_cache:get_records_by_name_and_type(Name, Type)),
    ?assertMatch([#dns_rr{}], erldns_zone_cache:get_records_by_name_and_type(Zone, Name, Type)),
    ?assertMatch([#dns_rr{}], erldns_zone_cache:get_records_by_name_and_type(Zone, Labels, Type)).

get_records_by_name_ent(_) ->
    Ent = dns_domain:to_lower(~"a2.a1.example.com"),
    Labels = dns_domain:split(dns_domain:to_lower(Ent)),
    Zone = erldns_zone_cache:lookup_zone(~"example.com"),
    ?assertMatch([#dns_rr{}, #dns_rr{}], erldns_zone_cache:get_records_by_name_ent(Zone, Ent)),
    ?assertMatch([#dns_rr{}, #dns_rr{}], erldns_zone_cache:get_records_by_name_ent(Zone, Labels)).

get_records_by_name_wildcard(_) ->
    Record = dns_domain:to_lower(~"a3.a2.a1.example.com"),
    Ent = dns_domain:to_lower(~"a2.a1.example.com"),
    Wild = dns_domain:to_lower(~"a.a-wild.example.com"),
    Labels = dns_domain:split(dns_domain:to_lower(Wild)),
    Zone = erldns_zone_cache:lookup_zone(~"example.com"),
    ?assertMatch([], erldns_zone_cache:get_records_by_name_wildcard(Zone, Ent)),
    ?assertMatch([], erldns_zone_cache:get_records_by_name_wildcard(Zone, Record)),
    ?assertMatch([#dns_rr{}], erldns_zone_cache:get_records_by_name_wildcard(Zone, Wild)),
    ?assertMatch([#dns_rr{}], erldns_zone_cache:get_records_by_name_wildcard(Zone, Labels)).

get_records_by_name_wildcard_strict(_) ->
    Record = dns_domain:to_lower(~"a3.a2.a1.example.com"),
    Ent = dns_domain:to_lower(~"a2.a1.example.com"),
    Wild = dns_domain:to_lower(~"a.a-wild.example.com"),
    Labels = dns_domain:split(dns_domain:to_lower(Wild)),
    Zone = erldns_zone_cache:lookup_zone(~"example.com"),
    ?assertMatch([#dns_rr{}], erldns_zone_cache:get_records_by_name_wildcard_strict(Zone, Ent)),
    ?assertMatch([#dns_rr{}], erldns_zone_cache:get_records_by_name_wildcard_strict(Zone, Record)),
    ?assertMatch([#dns_rr{}], erldns_zone_cache:get_records_by_name_wildcard_strict(Zone, Wild)),
    ?assertMatch([#dns_rr{}], erldns_zone_cache:get_records_by_name_wildcard_strict(Zone, Labels)).

get_authoritative_zone(_) ->
    NxName = dns_domain:to_lower(~"example.net"),
    Labels = dns_domain:split(dns_domain:to_lower(~"a.a-wild.example.com")),
    Name = dns_domain:to_lower(~"n4.n3.n2.n1.example.com"),
    ?assertMatch(zone_not_found, erldns_zone_cache:get_authoritative_zone(NxName)),
    ?assertMatch(#zone{}, erldns_zone_cache:get_authoritative_zone(Labels)),
    ?assertMatch(#zone{}, erldns_zone_cache:get_authoritative_zone(Name)).

get_delegations(_) ->
    NxName = dns_domain:to_lower(~"none.example.net"),
    Labels = dns_domain:split(dns_domain:to_lower(~"delegation.example.com")),
    Name = dns_domain:to_lower(~"delegation.example.com"),
    ?assertMatch([], erldns_zone_cache:get_delegations(NxName)),
    ?assertMatch([#dns_rr{}], erldns_zone_cache:get_delegations(Labels)),
    ?assertMatch([#dns_rr{}], erldns_zone_cache:get_delegations(Name)).

is_in_any_zone(_) ->
    NxName = dns_domain:to_lower(~"nxname.a1.example.net"),
    Name = dns_domain:to_lower(~"a1.example.com"),
    Labels = dns_domain:split(dns_domain:to_lower(Name)),
    ?assertMatch(false, erldns_zone_cache:is_in_any_zone(NxName)),
    ?assertMatch(true, erldns_zone_cache:is_in_any_zone(Name)),
    ?assertMatch(true, erldns_zone_cache:is_in_any_zone(Labels)).

is_name_in_zone(_) ->
    NxName = dns_domain:to_lower(~"a2.a1.example.net"),
    Ent = dns_domain:to_lower(~"a2.a1.example.com"),
    Name = dns_domain:to_lower(~"a3.a2.a1.example.com"),
    Wild = dns_domain:to_lower(~"a.a-wild.example.com"),
    Labels = dns_domain:split(dns_domain:to_lower(Name)),
    Zone = erldns_zone_cache:lookup_zone(~"example.com"),
    ?assertMatch(false, erldns_zone_cache:is_name_in_zone(Zone, NxName)),
    ?assertMatch(false, erldns_zone_cache:is_name_in_zone(Zone, Ent)),
    ?assertMatch(false, erldns_zone_cache:is_name_in_zone(Zone, Wild)),
    ?assertMatch(true, erldns_zone_cache:is_name_in_zone(Zone, Name)),
    ?assertMatch(true, erldns_zone_cache:is_name_in_zone(Zone, Labels)).

is_record_name_in_zone(_) ->
    NxName = dns_domain:to_lower(~"a2.a1.example.net"),
    Ent = dns_domain:to_lower(~"a2.a1.example.com"),
    Name = dns_domain:to_lower(~"a1.example.com"),
    Wild = dns_domain:to_lower(~"a.a-wild.example.com"),
    Labels = dns_domain:split(dns_domain:to_lower(Name)),
    Zone = erldns_zone_cache:lookup_zone(~"example.com"),
    ?assertMatch(false, erldns_zone_cache:is_record_name_in_zone(Zone, NxName)),
    ?assertMatch(false, erldns_zone_cache:is_record_name_in_zone(Zone, Ent)),
    ?assertMatch(true, erldns_zone_cache:is_record_name_in_zone(Zone, Wild)),
    ?assertMatch(true, erldns_zone_cache:is_record_name_in_zone(Zone, Name)),
    ?assertMatch(true, erldns_zone_cache:is_record_name_in_zone(Zone, Labels)).

is_record_name_in_zone_strict(_) ->
    NxName = dns_domain:to_lower(~"a2.a1.example.net"),
    Ent = dns_domain:to_lower(~"a2.a1.example.com"),
    Name = dns_domain:to_lower(~"a1.example.com"),
    Labels = dns_domain:split(dns_domain:to_lower(Name)),
    Zone = erldns_zone_cache:lookup_zone(~"example.com"),
    ?assertMatch(false, erldns_zone_cache:is_record_name_in_zone_strict(Zone, NxName)),
    ?assertMatch(true, erldns_zone_cache:is_record_name_in_zone_strict(Zone, Ent)),
    ?assertMatch(true, erldns_zone_cache:is_record_name_in_zone_strict(Zone, Name)),
    ?assertMatch(true, erldns_zone_cache:is_record_name_in_zone_strict(Zone, Labels)).

put_zone(_) ->
    ZoneName = dns_domain:to_lower(~"a1.put_zone.com"),
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
    ZoneNameNet = dns_domain:to_lower(~"example.net"),
    ZoneNet = erldns_zone_codec:build_zone(ZoneNameNet, ~"irrelevantDigest", [], []),
    ?assertMatch(zone_not_found, erldns_zone_cache:put_zone_rrset(ZoneNet, ~"a.example.net", 5, 1)),
    ZoneName = dns_domain:to_lower(~"example.com"),
    ZoneLabels = dns_domain:split(ZoneName),
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

put_zone_rrset_fetch_soa_match(_) ->
    ZoneName = dns_domain:to_lower(~"put_zone_rrset_fetch_soa_match.com"),
    SoaData = #dns_rrdata_soa{
        mname = ~"ns1.put_zone_rrset_fetch_soa_match.com",
        rname = ~"admin.put_zone_rrset_fetch_soa_match.com",
        serial = 12345,
        refresh = 555,
        retry = 666,
        expire = 777,
        minimum = 888
    },
    SOA = #dns_rr{
        name = ZoneName,
        type = ?DNS_TYPE_SOA,
        data = SoaData,
        ttl = 3600
    },
    Z = erldns_zone_codec:build_zone(ZoneName, ~"Digest-01", [SOA], []),
    ?assertMatch(ok, erldns_zone_cache:put_zone(Z)),
    ZoneBase = erldns_zone_cache:get_authoritative_zone(ZoneName),
    SoaRecordsInCache = erldns_zone_cache:get_records_by_name_and_type(ZoneName, ?DNS_TYPE_SOA),
    ?assertMatch(SoaRecordsInCache, ZoneBase#zone.authority),
    NewSoa = SOA#dns_rr{data = SoaData#dns_rrdata_soa{serial = 12346}},
    ?assertMatch(
        ok,
        erldns_zone_cache:put_zone_rrset(
            {ZoneName, ~"Digest-02", [NewSoa], []},
            ~"put_zone_rrset_fetch_soa_match.com",
            ?DNS_TYPE_SOA,
            1
        )
    ),
    ZoneModified = erldns_zone_cache:get_authoritative_zone(ZoneName),
    NewSoaRecordsInCache = erldns_zone_cache:get_records_by_name_and_type(ZoneName, ?DNS_TYPE_SOA),
    Comment = #{soa_in_zone => ZoneModified#zone.authority, soa_in_cache => NewSoaRecordsInCache},
    ?assertMatch(NewSoaRecordsInCache, ZoneModified#zone.authority, Comment).

put_zone_rrset_records_count_with_existing_rrset(_) ->
    ZoneName = dns_domain:to_lower(~"example.com"),
    ZoneLabels = dns_domain:split(ZoneName),
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
    ZoneName = dns_domain:to_lower(~"example.com"),
    ZoneLabels = dns_domain:split(ZoneName),
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
    ZoneName = dns_domain:to_lower(~"example.com"),
    ZoneLabels = dns_domain:split(ZoneName),
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
    ZoneName = dns_domain:to_lower(~"example-dnssec.com"),
    ZoneLabels = dns_domain:split(ZoneName),
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

put_zone_rrset_after_soa_delete(_) ->
    % This testcase simulates a situation when the zone needs to be updated even without the SOA
    % record present. This may happen for example during an Inbound AXFR.
    % Create a zone without SOA to simulate a deletion of SOA record
    ZoneName = dns_domain:to_lower(~"put_zone_rrset_after_soa_delete.com"),
    TxtData = #dns_rrdata_txt{
        txt = "put_zone_rrset_after_soa_delete zone without SOA"
    },
    TXT = #dns_rr{
        name = ZoneName,
        type = ?DNS_TYPE_TXT,
        data = TxtData,
        ttl = 3600
    },
    Z = erldns_zone_codec:build_zone(ZoneName, ~"Digest-01", [TXT], []),
    ?assertMatch(ok, erldns_zone_cache:put_zone(Z)),
    ZoneBase = erldns_zone_cache:lookup_zone(ZoneName),
    % No SOA
    ?assertMatch([], erldns_zone_cache:get_records_by_name_and_type(ZoneName, ?DNS_TYPE_SOA)),
    ?assertMatch([], ZoneBase#zone.authority),
    ?assertMatch(~"Digest-01", ZoneBase#zone.version),
    % TXT is saved
    TxtRecordsInCache = erldns_zone_cache:get_records_by_name_and_type(ZoneName, ?DNS_TYPE_TXT),
    ?assertMatch(TxtRecordsInCache, [TXT]),
    % Check that the zone can be updated, even without a SOA record
    NewTXT = TXT#dns_rr{
        data = #dns_rrdata_txt{
            txt = "put_zone_rrset_after_soa_delete update for a zone without SOA"
        }
    },
    ?assertMatch(
        ok,
        erldns_zone_cache:put_zone_rrset(
            {ZoneName, ~"Digest-02", [NewTXT], []},
            ~"put_zone_rrset_after_soa_delete.com",
            ?DNS_TYPE_TXT,
            1
        )
    ),
    % Still no SOA in cache
    ?assertMatch([], erldns_zone_cache:get_records_by_name_and_type(ZoneName, ?DNS_TYPE_SOA)),
    ZoneModified = erldns_zone_cache:lookup_zone(ZoneName),
    ?assertMatch([], ZoneModified#zone.authority),
    % But the digest is updated, and TXT record as well
    ?assertMatch(~"Digest-02", ZoneModified#zone.version),
    NewTXTRecordsInCache = erldns_zone_cache:get_records_by_name_and_type(ZoneName, ?DNS_TYPE_TXT),
    ?assertMatch(NewTXTRecordsInCache, [NewTXT]).

delete_zone_rrset_records_count_width_existing_rrset(_) ->
    ZoneName = dns_domain:to_lower(~"example.com"),
    ZoneLabels = dns_domain:split(ZoneName),
    ZoneBase = erldns_zone_cache:get_authoritative_zone(ZoneLabels),
    erldns_zone_cache:delete_zone_rrset(
        ZoneName,
        ~"irrelevantDigest",
        dns_domain:to_lower(~"cname.example.com"),
        ?DNS_TYPE_CNAME,
        1
    ),
    ZoneModified = erldns_zone_cache:get_authoritative_zone(ZoneLabels),
    % Deletes a CNAME RRSet with one record
    ?assertEqual(ZoneBase#zone.record_count - 1, ZoneModified#zone.record_count).

delete_zone_rrset_records_count_width_dnssec_zone_and_existing_rrset(_) ->
    ZoneName = dns_domain:to_lower(~"example-dnssec.com"),
    ZoneLabels = dns_domain:split(ZoneName),
    ZoneBase = erldns_zone_cache:get_authoritative_zone(ZoneLabels),
    erldns_zone_cache:delete_zone_rrset(
        ZoneName,
        ~"irrelevantDigest",
        dns_domain:to_lower(~"cname2.example-dnssec.com"),
        ?DNS_TYPE_CNAME,
        2
    ),
    ZoneModified = erldns_zone_cache:get_authoritative_zone(ZoneLabels),
    % Deletes a CNAME RRSet with one record + RRSig
    ?assertEqual(ZoneBase#zone.record_count - 2, ZoneModified#zone.record_count).

delete_zone_rrset_records_count_matches_cache(_) ->
    ZoneName = dns_domain:to_lower(~"example-dnssec.com"),
    ZoneLabels = dns_domain:split(ZoneName),
    erldns_zone_cache:delete_zone_rrset(
        ZoneName,
        ~"irrelevantDigest",
        dns_domain:to_lower(~"cname2.example-dnssec.com"),
        ?DNS_TYPE_CNAME,
        2
    ),
    ZoneModified = erldns_zone_cache:get_authoritative_zone(ZoneLabels),
    % Deletes a CNAME RRSet with one record + RRSig
    ?assertEqual(
        length(erldns_zone_cache:get_zone_records(ZoneName)), ZoneModified#zone.record_count
    ).

delete_zone_rrset_records_count_underflow(_) ->
    ZoneName = dns_domain:to_lower(~"example-dnssec.com"),
    ZoneLabels = dns_domain:split(ZoneName),
    ZoneBase = erldns_zone_cache:get_authoritative_zone(ZoneLabels),
    erldns_zone_cache:delete_zone_rrset(
        ZoneName,
        ~"irrelevantDigest",
        dns_domain:to_lower(~"cname2.example-dnssec.com"),
        ?DNS_TYPE_CNAME,
        1
    ),
    ZoneModified = erldns_zone_cache:get_authoritative_zone(ZoneLabels),
    % Deletes a CNAME RRSet with one record
    ?assertEqual(ZoneBase#zone.record_count, ZoneModified#zone.record_count).

delete_zone_rrset_records_zone_not_found(_) ->
    ZoneName = dns_domain:to_lower(~"example-dnssec.net"),
    Ret = erldns_zone_cache:delete_zone_rrset(
        ZoneName,
        ~"irrelevantDigest",
        dns_domain:to_lower(~"cname2.example-dnssec.com"),
        ?DNS_TYPE_CNAME,
        1
    ),
    ?assertEqual(zone_not_found, Ret).

init_supervision_tree(Config, Role) ->
    Self = self(),
    Fun = fun() ->
        setup_test(Config, Role),
        Self ! continue,
        receive
            stop -> ok
        end
    end,
    Pid = spawn(Fun),
    receive
        continue -> ok
    end,
    {Role, Pid}.

setup_test(_Config, loader) ->
    application:set_env(erldns, zones, #{codecs => [sample_custom_zone_codec]}),
    {ok, _} = erldns_zones:start_link();
setup_test(Config, cache) ->
    {ok, _} = erldns_zones:start_link(),
    DataDir = proplists:get_value(data_dir, Config),
    LoadConfig1 = #{path => filename:join(DataDir, "standard.json")},
    ?assertMatch(1, erldns_zone_loader:load_zones(LoadConfig1)),
    LoadConfig2 = #{path => filename:join(DataDir, "dnssec-zone.json")},
    ?assertMatch(1, erldns_zone_loader:load_zones(LoadConfig2));
setup_test(_Config, codec) ->
    {ok, _CachePid} = erldns_zone_cache:start_link(),
    {ok, _CodecPid} = erldns_zone_codec:start_link(),
    case ets:info(erldns_zones_table) of
        undefined -> erlang:error(ets_table_not_found);
        _ -> ok
    end.

unique_name(TestCase) ->
    Name = atom_to_binary(TestCase),
    UniqueId = integer_to_binary(erlang:unique_integer([positive, monotonic])),
    dns_domain:to_lower(erlang:iolist_to_binary([Name, ~".", UniqueId, ~".com."])).

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
        },
        {
          "context": [],
          "data": {
            "usage": 3,
            "selector": 1,
            "matching_type": 1,
            "certificate": "DE38C1C08EB239D76B45DA575C70151CE7DA13A935BF5FB887B4E43664D6F728"
          },
          "name": "_443._tcp.example.com",
          "ttl": 3600,
          "type": "TLSA"
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
