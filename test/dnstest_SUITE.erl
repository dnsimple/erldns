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
            {listeners, [#{name => inet_1, ip => {127, 0, 0, 1}, port => 8053}]},
            {zones, #{path => code:priv_dir(dnstest)}}
        ]}
    ],
    Config = app_helper:start_erldns(Config0, AppConfig),
    DnsTestConfig = [{dnstest, [{inet4, {127, 0, 0, 1}}, {port, 8053}]}],
    application:set_env(DnsTestConfig),
    {ok, _} = application:ensure_all_started([dnstest]),
    Config.

-spec end_per_suite(ct_suite:ct_config()) -> term().
end_per_suite(Config) ->
    app_helper:stop(Config),
    PrivDir = proplists:get_value(priv_dir, Config),
    File = filename:join([PrivDir, "dnstest.log"]),
    ?assert(filelib:is_file(File)),
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
        nsec_nxname_ent,
        ns_zonecut_child_cname
    ].
