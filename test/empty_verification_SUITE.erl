-module(empty_verification_SUITE).
-compile([export_all, nowarn_export_all]).

-behaviour(ct_suite).

-include_lib("stdlib/include/assert.hrl").
-include_lib("dns_erlang/include/dns.hrl").

-spec all() -> [ct_suite:ct_test_def()].
all() ->
    [{group, all}].

-spec groups() -> [ct_suite:ct_group_def()].
groups() ->
    [{all, [parallel], [refused, empty, none, not_resolved]}].

-spec init_per_suite(ct_suite:ct_config()) -> ct_suite:ct_config().
init_per_suite(Config) ->
    application:ensure_all_started([telemetry]),
    Events = [
        [erldns, handler, refused],
        [erldns, handler, empty]
    ],
    ok = telemetry:attach_many(?MODULE, Events, fun ?MODULE:telemetry_handler/4, []),
    Config.

-spec end_per_suite(ct_suite:ct_config()) -> term().
end_per_suite(_) ->
    application:stop(telemetry).

%% Tests
refused(_) ->
    Opts = maps:merge(def_opts(), #{resolved => true}),
    ?assertMatch(
        #dns_message{},
        erldns_empty_verification:call(#dns_message{rc = ?DNS_RCODE_REFUSED}, Opts)
    ),
    assert_telemetry_event(?FUNCTION_NAME).

empty(_) ->
    Opts = maps:merge(def_opts(), #{resolved => true}),
    ?assertMatch(
        #dns_message{},
        erldns_empty_verification:call(#dns_message{}, Opts)
    ),
    assert_telemetry_event(?FUNCTION_NAME).

none(_) ->
    Opts = maps:merge(def_opts(), #{resolved => true}),
    ?assertMatch(
        #dns_message{},
        erldns_empty_verification:call(#dns_message{anc = 1, auc = 2}, Opts)
    ),
    assert_no_telemetry_event(?FUNCTION_NAME).

not_resolved(_) ->
    ?assertMatch(
        #dns_message{},
        erldns_empty_verification:call(#dns_message{anc = 1, auc = 2}, def_opts())
    ),
    assert_no_telemetry_event(?FUNCTION_NAME).

def_opts() ->
    erldns_pipeline:def_opts().

telemetry_handler(EventName, _, _, _) ->
    ct:pal("EventName ~p~n", [EventName]),
    self() ! EventName.

assert_telemetry_event(Name) ->
    receive
        [erldns, handler, Name] ->
            ok
    after 1000 ->
        ct:fail("Telemetry event not triggered: ~p", [Name])
    end.

assert_no_telemetry_event(Name) ->
    receive
        [erldns, handler, Name] -> ct:fail("Telemetry event not triggered: ~p", [Name])
    after 100 -> ok
    end.
