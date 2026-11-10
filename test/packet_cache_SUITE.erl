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
        answers_with_additional_records_are_hit,
        names_are_case_insensitive,
        query_options_do_not_split_entries
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
    start_cache(),
    Msg0 = query(~"example.com", ?DNS_TYPE_A),
    Opts = opts(Msg0),
    {Msg1, Opts1} = erldns_packet_cache:call(Msg0, Opts),
    ServFail = Msg1#dns_message{aa = true, rc = ?DNS_RCODE_SERVFAIL},
    ?assertEqual(ServFail, erldns_packet_cache:call(ServFail, Opts1)),
    ?assertMatch({_, #{erldns_packet_cache := {miss, _}}}, erldns_packet_cache:call(Msg0, Opts)).

answers_with_additional_records_are_hit(_) ->
    start_cache(),
    Msg0 = (query(~"example.com", ?DNS_TYPE_MX))#dns_message{additional = [#dns_optrr{}]},
    Opts = opts(Msg0),
    {Msg1, Opts1} = erldns_packet_cache:call(Msg0, Opts),
    Glue = #dns_rr{name = <<"mx.example.com">>, type = ?DNS_TYPE_A},
    Answer = Msg1#dns_message{aa = true, additional = [#dns_optrr{}, Glue]},
    {_, #{erldns_packet_cache := cached}} = erldns_packet_cache:call(Answer, Opts1),
    ?assertMatch({Answer, #{resolved := true}}, erldns_packet_cache:call(Msg0, Opts)).

names_are_case_insensitive(_) ->
    start_cache(),
    Msg0 = query(~"Example.COM", ?DNS_TYPE_A),
    {Msg1, Opts1} = erldns_packet_cache:call(Msg0, opts(Msg0)),
    Answer = Msg1#dns_message{qr = true, aa = true, answers = [#dns_rr{name = ~"example.com"}]},
    {_, #{erldns_packet_cache := cached}} = erldns_packet_cache:call(Answer, Opts1),
    Msg2 = (query(~"eXAMPLE.com", ?DNS_TYPE_A))#dns_message{id = 42, rd = true},
    {Hit, #{resolved := true}} = erldns_packet_cache:call(Msg2, opts(Msg2)),
    ?assertEqual(
        Answer#dns_message{id = 42, rd = true, questions = Msg2#dns_message.questions}, Hit
    ).

%% erldns_edns takes the query's options out of the message, so queries that only differ by them,
%% such as each client's cookie, share an entry, and none of them is sent back.
query_options_do_not_split_entries(_) ->
    start_cache(),
    [Msg0, Msg1] = [with_cookie(query(~"example.com", ?DNS_TYPE_A), C) || C <- [1, 2]],
    {Msg2, Opts2} = erldns_packet_cache:call(Msg0, opts(Msg0)),
    Answer = Msg2#dns_message{aa = true, answers = [#dns_rr{name = ~"example.com"}]},
    {_, #{erldns_packet_cache := cached}} = erldns_packet_cache:call(Answer, Opts2),
    {Hit, #{resolved := true}} = erldns_packet_cache:call(Msg1, opts(Msg1)),
    ?assertMatch(#dns_message{additional = [#dns_optrr{data = []}]}, Hit).

with_cookie(Msg, Client) ->
    OptRR = #dns_optrr{data = [#dns_opt_cookie{client = <<Client:64>>}]},
    {Msg1, _} = erldns_edns:call(Msg#dns_message{additional = [OptRR]}, def_opts()),
    Msg1.

test_calls() ->
    Msg0 = query(~"example.com", ?DNS_TYPE_A),
    Opts = opts(Msg0),
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

start_cache() ->
    application:set_env(erldns, packet_cache, #{}),
    {ok, _} = pg:start_link(erldns),
    {ok, _} = erldns_packet_cache:start_link().

query(Name, Type) ->
    #dns_message{qc = 1, questions = [#dns_query{name = Name, type = Type}]}.

opts(Msg) ->
    {Msg, Opts} = erldns_questions:call(Msg, erldns_packet_cache:prepare(def_opts())),
    Opts.

def_opts() ->
    erldns_pipeline:def_opts().
