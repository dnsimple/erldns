-module(dnstest_SUITE).
-compile([export_all, nowarn_export_all]).

-behaviour(ct_suite).

-include_lib("stdlib/include/assert.hrl").

-spec all() -> [ct_suite:ct_test_def()].
all() ->
    [{group, all}].

-spec groups() -> [ct_suite:ct_group_def()].
groups() ->
    [
        {all, [parallel], [
            pdns_definitions,
            pdns_dnssec_definitions,
            erldns_definitions,
            erldns_dnssec_definitions
        ]}
    ].

-spec init_per_suite(ct_suite:ct_config()) -> ct_suite:ct_config().
init_per_suite(Config) ->
    Servers = [
        [
            {name, inet_localhost_1},
            {address, "127.0.0.1"},
            {port, 8053},
            {family, inet},
            {processes, 10}
        ]
    ],
    application:set_env(erldns, servers, Servers),
    application:set_env(erldns, ff_use_txts_field, true),
    application:set_env(dnstest, inet4, {127, 0, 0, 1}),
    application:set_env(dnstest, port, 8053),
    application:ensure_all_started([erldns, dnstest]),
    FileName = filename:join([code:priv_dir(dnstest), "zones.json"]),
    {ok, _} = erldns_storage:load_zones(FileName),
    Config.

-spec end_per_suite(ct_suite:ct_config()) -> term().
end_per_suite(Config) ->
    application:stop(erldns),
    Config.

-spec init_per_group(ct_suite:ct_groupname(), ct_suite:ct_config()) -> ct_suite:ct_config().
init_per_group(_, Config) ->
    Config.

-spec end_per_group(ct_suite:ct_groupname(), ct_suite:ct_config()) -> term().
end_per_group(_, _Config) ->
    ok.

-spec init_per_testcase(ct_suite:ct_testcase(), ct_suite:ct_config()) -> ct_suite:ct_config().
init_per_testcase(_, Config) ->
    dnstest_metrics:start(),
    Config.

-spec end_per_testcase(ct_suite:ct_testcase(), ct_suite:ct_config()) -> term().
end_per_testcase(_, Config) ->
    Config.

%% Tests
pdns_definitions(_) ->
    Results = dnstest_harness:run(dnstest_definitions:pdns_definitions(), passing()),
    assert_result(?FUNCTION_NAME, Results).

pdns_dnssec_definitions(_) ->
    Results = dnstest_harness:run(dnstest_definitions:pdns_dnssec_definitions(), passing()),
    assert_result(?FUNCTION_NAME, Results).

erldns_definitions(_) ->
    Results = dnstest_harness:run(dnstest_definitions:erldns_definitions(), passing()),
    assert_result(?FUNCTION_NAME, Results).

erldns_dnssec_definitions(_) ->
    Results = dnstest_harness:run(dnstest_definitions:erldns_dnssec_definitions(), passing()),
    assert_result(?FUNCTION_NAME, Results).

assert_result(_Definitions, Results) ->
    All = lists:all(fun(#{result := Result}) -> true =:= Result end, Results),
    ?assert(All, #{failed => lists:filter(fun(#{result := Result}) -> true =/= Result end, Results)}).

passing() ->
    [
        "any_nxdomain",
        "any_wildcard",
        "apex_level_a_but_no_a",
        "apex_level_a",
        "basic_a_resolution",
        "basic_aaaa_resolution",
        "basic_hinfo",
        "basic_soa_resolution",
        "basic_srv_resolution",
        "basic_txt_resolution",
        "cname_and_wildcard_at_root",
        "cname_and_wildcard_but_no_correct_type",
        "cname_and_wildcard",
        "cname_but_no_correct_type",
        "cname_loop_breakout",
        "cname_to_nxdomain_any",
        "cname_to_nxdomain",
        "cname_to_referral",
        "cname_to_unauth_any",
        "cname_to_unauth",
        "cname_wildcard_chain",
        "cross_domain_cname_to_wildcard",
        "direct_dnskey",
        "direct_wildcard",
        "double_srv",
        "double",
        "ds_at_apex_noerror",
        "ent_rr_enclosed_in_ent",
        "ent_wildcard_below_ent",
        "external_cname_pointer",
        "five_levels_wildcard_one_below_apex",
        "five_levels_wildcard",
        "internal_referral_glue",
        "long_name",
        "multi_step_cname_resolution",
        "multi_txt_escape_resolution",
        "multi_txt_resolution",
        "mx_to_cname",
        "naptr",
        "non_existing_record_other_types_exist_ns",
        "non_existing_record_other_types_exist",
        "nx_domain_for_unknown_record",
        "obscured_wildcard",
        "one_step_cname_resolution",
        "out_of_baliwick_referral",
        "pretty_big_packet",
        "rp",
        "same_level_referral_soa",
        "same_level_referral",
        "too_big_for_udp_query_no_truncate_additional",
        "too_big_for_udp_query",
        "wildcard_overlaps_delegation",
        "wrong_type_wildcard",
        "ns_a_record",
        "ns_aaaa_record",
        "cname_case"
    ].

%% TOOD: these are failing and we need to investigate why and fix,
%% until we can run all of them
failing() ->
    [
        "8_bit_txt",
        "unknown_domain",
        "any_query",
        "apex_level_ns",
        "basic_ns_resolution",
        "escaped_txt_1",
        "glue_record",
        "glue_referral",
        "internal_referral",
        "mx_case_sensitivity_with_ap",
        "mx_with_simple_additional_processing",
        "ns_at_delegation",
        "ns_with_identical_glue",
        "root_cname",
        "root_mx",
        "root_ns",
        "root_srv",
        "very_long_text",
        "ns_zonecut",
        "ns_zonecut_child_cname",
        "ns_recursion_breakout",
        "cname_wildcard_cover",
        "caa_record",
        "cname_to_nxdomain_any_dnssec",
        "cname_to_unauth_any_dnssec",
        "cname_to_unauth_dnssec",
        "direct_dnskey_dnssec",
        "double_dnssec",
        "direct_rrsig",
        "dnssec_soa",
        "dnssec_ns",
        "dnssec_a",
        "dnssec_a_with_udp_payload_size",
        "dnssec_cname",
        "dnssec_follow_cname",
        "dnssec_cds",
        "dnssec_cdnskey",
        "dnssec_dnskey",
        "nsec_name",
        "nsec_name_mixed_case",
        "nsec_type",
        "nsec_name_any",
        "nsec_type_any",
        "nsec_rr_type_bitmap_wildcard",
        "cname_to_nxdomain_dnssec",
        "cname_wildcard_chain_dnssec"
    ].
