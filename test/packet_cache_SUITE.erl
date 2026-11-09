-module(packet_cache_SUITE).
-compile([export_all, nowarn_export_all]).

-behaviour(ct_suite).

-include_lib("stdlib/include/assert.hrl").
-include_lib("dns_erlang/include/dns.hrl").

-spec all() -> [ct_suite:ct_test_def()].
all() ->
    [
        is_enabled_true,
        is_enabled_default,
        start_when_disabled,
        start_when_enabled_with_default_ttl,
        start_when_enabled_with_custom_ttl,
        errors_are_not_cached,
        answers_with_additional_records_are_hit
    ].

-spec init_per_suite(ct_suite:ct_config()) -> ct_suite:ct_config().
init_per_suite(Config) ->
    application:ensure_all_started([telemetry]),
    Config.

-spec end_per_suite(ct_suite:ct_config()) -> term().
end_per_suite(_) ->
    application:stop(telemetry).

%% Tests
is_enabled_true(_) ->
    application:set_env(erldns, packet_cache, #{enabled => true}),
    ?assertMatch(#{erldns_packet_cache := false}, erldns_packet_cache:prepare(def_opts())).

is_enabled_default(_) ->
    application:set_env(erldns, packet_cache, #{}),
    ?assertMatch(#{erldns_packet_cache := false}, erldns_packet_cache:prepare(def_opts())).

start_when_disabled(_) ->
    application:set_env(erldns, packet_cache, #{enabled => false}),
    ?assertEqual(disabled, erldns_packet_cache:prepare(def_opts())),
    ?assertMatch({ok, _}, pg:start_link(erldns)),
    ?assertMatch(ignore, erldns_packet_cache:start_link()).

start_when_enabled_with_default_ttl(_) ->
    application:set_env(erldns, packet_cache, #{}),
    ?assertMatch({ok, _}, pg:start_link(erldns)),
    ?assertMatch({ok, _}, erldns_packet_cache:start_link()),
    test_calls().

start_when_enabled_with_custom_ttl(_) ->
    application:set_env(erldns, packet_cache, #{ttl => 30000}),
    ?assertMatch({ok, _}, pg:start_link(erldns)),
    ?assertMatch({ok, _}, erldns_packet_cache:start_link()),
    test_calls().

errors_are_not_cached(_) ->
    application:set_env(erldns, packet_cache, #{}),
    ?assertMatch({ok, _}, pg:start_link(erldns)),
    ?assertMatch({ok, _}, erldns_packet_cache:start_link()),
    Qs = [#dns_query{name = <<"example.com">>, type = ?DNS_TYPE_A}],
    Msg0 = #dns_message{qc = 1, questions = Qs},
    Opts = erldns_packet_cache:prepare(def_opts()),
    {Msg1, Opts1} = erldns_packet_cache:call(Msg0, Opts),
    ServFail = Msg1#dns_message{aa = true, rc = ?DNS_RCODE_SERVFAIL},
    ?assertEqual(ServFail, erldns_packet_cache:call(ServFail, Opts1)),
    ?assertMatch({_, #{erldns_packet_cache := {miss, _}}}, erldns_packet_cache:call(Msg0, Opts)).

answers_with_additional_records_are_hit(_) ->
    application:set_env(erldns, packet_cache, #{}),
    ?assertMatch({ok, _}, pg:start_link(erldns)),
    ?assertMatch({ok, _}, erldns_packet_cache:start_link()),
    Qs = [#dns_query{name = <<"example.com">>, type = ?DNS_TYPE_MX}],
    Msg0 = #dns_message{qc = 1, questions = Qs, additional = [#dns_optrr{}]},
    Opts = erldns_packet_cache:prepare(def_opts()),
    {Msg1, Opts1} = erldns_packet_cache:call(Msg0, Opts),
    Glue = #dns_rr{name = <<"mx.example.com">>, type = ?DNS_TYPE_A},
    Answer = Msg1#dns_message{aa = true, additional = [#dns_optrr{}, Glue]},
    {_, #{erldns_packet_cache := cached}} = erldns_packet_cache:call(Answer, Opts1),
    ?assertMatch({Answer, #{resolved := true}}, erldns_packet_cache:call(Msg0, Opts)).

test_calls() ->
    Qs = [#dns_query{name = <<"example.com">>, type = ?DNS_TYPE_A}],
    Msg0 = #dns_message{qc = 1, questions = Qs},
    Opts = erldns_packet_cache:prepare(def_opts()),
    %% test that the first call is a miss
    {Msg1, Opts1} = erldns_packet_cache:call(Msg0, Opts),
    ?assertMatch(#{erldns_packet_cache := {miss, _}}, Opts1),
    %% test that a consecutive call with Authoritative flag seg to true gets cached
    {_Msg2, Opts2} = erldns_packet_cache:call(Msg1#dns_message{aa = true}, Opts1),
    ?assertMatch(#{erldns_packet_cache := cached}, Opts2),
    %% test that a later equivalent call is a hit and gets resolved
    {_Msg3, Opts3} = erldns_packet_cache:call(Msg0, Opts),
    ?assertMatch(#{erldns_packet_cache := cached, resolved := true}, Opts3),
    %% test that any other condition is ignored
    MsgIgnore = erldns_packet_cache:call(Msg1, Opts1),
    ?assertMatch(#dns_message{}, MsgIgnore),
    %% test that after a cleared cache next checks are misses
    _ = erldns_packet_cache:clear(),
    {_, Opts4} = erldns_packet_cache:call(Msg0, Opts),
    ?assertMatch(#{erldns_packet_cache := {miss, _}}, Opts4).

def_opts() ->
    erldns_pipeline:def_opts().
