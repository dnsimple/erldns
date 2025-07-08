-module(questions_SUITE).
-compile([export_all, nowarn_export_all]).

-behaviour(ct_suite).

-include_lib("stdlib/include/assert.hrl").
-include_lib("dns_erlang/include/dns.hrl").

-spec all() -> [ct_suite:ct_test_def()].
all() ->
    [{group, all}].

-spec groups() -> [ct_suite:ct_group_def()].
groups() ->
    [{all, [parallel], [empty, one_question, many_questions]}].

-spec init_per_suite(ct_suite:ct_config()) -> ct_suite:ct_config().
init_per_suite(Config) ->
    application:ensure_all_started([telemetry]),
    Events = [
        [erldns, pipeline, questions]
    ],
    ok = telemetry:attach_many(?MODULE, Events, fun ?MODULE:telemetry_handler/4, []),
    Config.

-spec end_per_suite(ct_suite:ct_config()) -> term().
end_per_suite(_) ->
    application:stop(telemetry).

%% Tests
empty(_) ->
    Msg = #dns_message{},
    ?assertMatch({stop, #dns_message{}}, erldns_questions:call(Msg, def_opts())),
    assert_no_telemetry_event().

one_question(_) ->
    Q = #dns_query{name = ~"example.com", type = ?DNS_TYPE_ANY},
    Msg = #dns_message{qc = 1, questions = [Q]},
    ?assertMatch({Msg, _}, erldns_questions:call(Msg, def_opts())),
    assert_no_telemetry_event().

many_questions(_) ->
    Q = #dns_query{name = ~"example.com", type = ?DNS_TYPE_ANY},
    Msg = #dns_message{qc = 2, questions = [Q, Q]},
    ?assertMatch({#dns_message{qc = 1}, _}, erldns_questions:call(Msg, def_opts())),
    assert_telemetry_event().

def_opts() ->
    erldns_pipeline:def_opts().

telemetry_handler(EventName, _, _, _) ->
    ct:pal("EventName ~p~n", [EventName]),
    self() ! EventName.

assert_telemetry_event() ->
    receive
        [erldns, pipeline, questions] ->
            ok
    after 1000 ->
        ct:fail("Telemetry event not triggered: questions")
    end.

assert_no_telemetry_event() ->
    receive
        [erldns, pipeline, questions] ->
            ct:fail("Telemetry event not triggered: questions")
    after 100 ->
        ok
    end.
