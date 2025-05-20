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
init_per_suite(Config0) ->
    AppConfig = [
        {erldns, [
            {servers, [
                [
                    {name, inet_localhost_1},
                    {address, "0.0.0.0"},
                    {port, 8053},
                    {family, inet},
                    {with_tcp, false}
                ]
            ]},
            {listeners, #{localhost => #{protocol => tcp, port => 8053}}},
            {zones, code:priv_dir(dnstest)},
            {ff_use_txts_field, true}
        ]},
        {kernel, [
            {logger_level, info},
            {logger, [{handler, default, logger_std_h, #{}}]}
        ]}
    ],
    Config = app_helper:start_erldns(Config0, AppConfig),
    DnsTestConfig = [{dnstest, [{inet4, {127, 0, 0, 1}}, {port, 8053}]}],
    application:set_env(DnsTestConfig),
    {ok, _} = application:ensure_all_started([dnstest]),
    Config.

-spec end_per_suite(ct_suite:ct_config()) -> term().
end_per_suite(Config) ->
    application:stop(erldns),
    app_helper:stop(Config),
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
    Result = dnstest_harness:run(dnstest_definitions:pdns_definitions()),
    assert(?FUNCTION_NAME, Result).

pdns_dnssec_definitions(_) ->
    Result = dnstest_harness:run(dnstest_definitions:pdns_dnssec_definitions()),
    assert(?FUNCTION_NAME, Result).

erldns_definitions(_) ->
    Result = dnstest_harness:run(dnstest_definitions:erldns_definitions()),
    assert(?FUNCTION_NAME, Result).

erldns_dnssec_definitions(_) ->
    Result = dnstest_harness:run(dnstest_definitions:erldns_dnssec_definitions()),
    assert(?FUNCTION_NAME, Result).

assert(_Definitions, Results) ->
    All = lists:filter(
        fun(#{name := Name, result := Result}) ->
            true =/= Result andalso not lists:member(Name, failing())
        end,
        Results
    ),
    ?assertMatch([], All).

%% TOOD: these are failing and we need to investigate why and fix,
%% until we can run all of them
failing() ->
    [
        nsec_alias_a,
        nsec_alias_aaaa,
        nsec_alias_other,
        nsec_nxname_ent,
        ns_zonecut_child_cname
    ].
