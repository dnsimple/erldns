-module(query_throttle_SUITE).
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
        start_when_enabled_with_default_limit,
        start_when_enabled_with_custom_limit
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
    application:set_env(erldns, query_throttle, #{enabled => true}),
    ?assertMatch(#{packet_throttle_limit := _}, erldns_query_throttle:prepare(def_opts())).

is_enabled_default(_) ->
    application:set_env(erldns, query_throttle, #{}),
    ?assertMatch(#{packet_throttle_limit := _}, erldns_query_throttle:prepare(def_opts())).

start_when_disabled(_) ->
    application:set_env(erldns, query_throttle, #{enabled => false}),
    ?assertEqual(disabled, erldns_query_throttle:prepare(def_opts())),
    ?assertMatch(ignore, erldns_query_throttle:start_link()).

start_when_enabled_with_default_ttl(_) ->
    application:set_env(erldns, query_throttle, #{}),
    ?assertMatch({ok, _}, pg:start_link(erldns)),
    ?assertMatch({ok, _}, erldns_query_throttle:start_link()),
    test_calls(1).

start_when_enabled_with_custom_ttl(_) ->
    application:set_env(erldns, query_throttle, #{ttl => 30000}),
    ?assertMatch({ok, _}, pg:start_link(erldns)),
    ?assertMatch({ok, _}, erldns_query_throttle:start_link()),
    test_calls(1).

start_when_enabled_with_default_limit(_) ->
    application:set_env(erldns, query_throttle, #{}),
    ?assertMatch({ok, _}, pg:start_link(erldns)),
    ?assertMatch({ok, _}, erldns_query_throttle:start_link()),
    test_calls(1).

start_when_enabled_with_custom_limit(_) ->
    application:set_env(erldns, query_throttle, #{limit => 5}),
    ?assertMatch({ok, _}, pg:start_link(erldns)),
    ?assertMatch({ok, _}, erldns_query_throttle:start_link()),
    test_calls(5).

test_calls(Limit) ->
    Q = #dns_query{name = <<"example.com">>, type = ?DNS_TYPE_ANY},
    Msg0 = #dns_message{qc = 1, questions = [Q]},
    Opts = erldns_query_throttle:prepare(def_opts()),
    throttled(Msg0, Limit, Opts#{host := {1, 2, 3, 4}}),
    not_throttled(Msg0, Q, Opts).

throttled(Msg0, Limit, Opts) ->
    %% Test that below the limit passes
    [
        ?assertMatch(
            #dns_message{},
            erldns_query_throttle:call(Msg0, Opts)
        )
     || _ <- lists:seq(1, Limit)
    ],
    %% Test that one more is throttled
    ?assertMatch(
        {stop, #dns_message{rc = ?DNS_RCODE_NOERROR}},
        erldns_query_throttle:call(Msg0, Opts)
    ),
    %% test that after a cleared throttle the next one passes
    _ = erldns_query_throttle:clear(),
    ?assertMatch(
        #dns_message{},
        erldns_query_throttle:call(Msg0, Opts)
    ).

not_throttled(Msg0, Q, Opts) ->
    %% Test that regular queries are not throttled
    Regular = Msg0#dns_message{questions = [Q#dns_query{type = ?DNS_TYPE_A}]},
    [erldns_query_throttle:call(Regular, Opts) || _ <- lists:seq(1, 10)],
    ?assertMatch(
        #dns_message{},
        erldns_query_throttle:call(Regular, Opts)
    ),
    %% Test that TCP queries are not throttled
    ?assertMatch(
        #dns_message{},
        erldns_query_throttle:call(Msg0, Opts#{transport := tcp})
    ),
    %% Test that localhost queries are not throttled
    ?assertMatch(
        #dns_message{},
        erldns_query_throttle:call(Msg0, Opts#{host := {127, 0, 0, 1}})
    ),
    ?assertMatch(
        #dns_message{},
        erldns_query_throttle:call(Msg0, Opts#{host := {0, 0, 0, 0, 0, 0, 0, 1}})
    ).

def_opts() ->
    erldns_pipeline:def_opts().
