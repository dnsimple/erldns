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
    {ok, _} = erldns_storage:load_zones(code:priv_dir(dnstest)),
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
    Passing = dnstest_harness:run(dnstest_definitions:pdns_definitions(), passing()),
    Failing = dnstest_harness:run(dnstest_definitions:pdns_definitions(), failing()),
    assert_passing(?FUNCTION_NAME, Passing),
    assert_failing(?FUNCTION_NAME, Failing).

pdns_dnssec_definitions(_) ->
    Passing = dnstest_harness:run(dnstest_definitions:pdns_dnssec_definitions(), passing()),
    Failing = dnstest_harness:run(dnstest_definitions:pdns_dnssec_definitions(), failing()),
    assert_passing(?FUNCTION_NAME, Passing),
    assert_failing(?FUNCTION_NAME, Failing).

erldns_definitions(_) ->
    Passing = dnstest_harness:run(dnstest_definitions:erldns_definitions(), passing()),
    Failing = dnstest_harness:run(dnstest_definitions:erldns_definitions(), failing()),
    assert_passing(?FUNCTION_NAME, Passing),
    assert_failing(?FUNCTION_NAME, Failing).

erldns_dnssec_definitions(_) ->
    Passing = dnstest_harness:run(dnstest_definitions:erldns_dnssec_definitions(), passing()),
    Failing = dnstest_harness:run(dnstest_definitions:erldns_dnssec_definitions(), failing()),
    assert_passing(?FUNCTION_NAME, Passing),
    assert_failing(?FUNCTION_NAME, Failing).

assert_passing(_Definitions, Results) ->
    All = lists:all(fun(#{result := Result}) -> true =:= Result end, Results),
    ?assert(All, #{failed => lists:filter(fun(#{result := Result}) -> true =/= Result end, Results)}).

assert_failing(_Definitions, Results) ->
    All = lists:all(fun(#{result := Result}) -> true =/= Result end, Results),
    ?assert(All, #{failed => lists:filter(fun(#{result := Result}) -> true =:= Result end, Results)}).

passing() ->
    [
             "8_bit_txt",
        "any_nxdomain",
        "any_query",
        "any_wildcard",
        "apex_level_a_but_no_a",
        "apex_level_a",
        "apex_level_ns",
        "basic_a_resolution",
        "basic_aaaa_resolution",
        "basic_hinfo",
        "basic_ns_resolution",
        "basic_soa_resolution",
        "basic_srv_resolution",
        "basic_txt_resolution",
        "caa_record",
        "cname_and_wildcard_at_root",
        "cname_and_wildcard_but_no_correct_type",
        "cname_and_wildcard",
        "cname_but_no_correct_type",
        "cname_case",
        "cname_loop_breakout",
        "cname_to_nxdomain_any_dnssec",
        "cname_to_nxdomain_any",
        "cname_to_nxdomain_dnssec",
        "cname_to_nxdomain",
        "cname_to_referral",
        "cname_to_unauth_any_dnssec",
        "cname_to_unauth_any",
        "cname_to_unauth_dnssec",
        "cname_to_unauth",
        "cname_wildcard_chain_dnssec"
        "cname_wildcard_chain",
        "cname_wildcard_cover",
        "cross_domain_cname_to_wildcard",
        "direct_dnskey_dnssec",
        "direct_dnskey",
        "direct_rrsig",
        "direct_wildcard",
        "dnssec_a_with_udp_payload_size",
        "dnssec_a",
        "dnssec_cdnskey",
        "dnssec_cds",
        "dnssec_cname",
        "dnssec_dnskey",
        "dnssec_follow_cname",
        "dnssec_ns",
        "dnssec_soa",
        "double_dnssec",
        "double_srv",
        "double",
        "ds_at_apex_noerror",
        "ent_rr_enclosed_in_ent",
        "ent_wildcard_below_ent",
        "escaped_txt_1",
        "external_cname_pointer",
        "five_levels_wildcard_one_below_apex",
        "five_levels_wildcard",
        "glue_record",
        "glue_referral",
        "internal_referral_glue",
        "internal_referral",
        "long_name",
        "multi_step_cname_resolution",
        "multi_txt_escape_resolution",
        "multi_txt_resolution",
        "mx_case_sensitivity_with_ap",
        "mx_to_cname",
        "mx_with_simple_additional_processing",
        "naptr",
        "non_existing_record_other_types_exist_ns",
        "non_existing_record_other_types_exist",
        "ns_a_record",
        "ns_aaaa_record",
        "ns_at_delegation",
        "ns_recursion_breakout",
        "ns_with_identical_glue",
        "ns_zonecut",
        "nsec_name_any",
        "nsec_name_mixed_case",
        "nsec_name",
        "nsec_rr_type_bitmap_wildcard",
        "nsec_type_any",
        "nsec_type",
        "nx_domain_for_unknown_record",
        "obscured_wildcard",
        "one_step_cname_resolution",
        "out_of_baliwick_referral",
        "pretty_big_packet",
        "root_cname",
        "root_mx",
        "root_ns",
        "root_srv",
        "rp",
        "same_level_referral_soa",
        "same_level_referral",
        "too_big_for_udp_query_no_truncate_additional",
        "too_big_for_udp_query",
        "unknown_domain",
        "very_long_text",
        "wildcard_overlaps_delegation",
        "wrong_type_wildcard"
    ].

%% TOOD: these are failing and we need to investigate why and fix,
%% until we can run all of them
failing() ->
    [
        "ns_zonecut_child_cname"
    ].
