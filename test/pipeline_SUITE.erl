-module(pipeline_SUITE).
-compile([export_all, nowarn_export_all]).

-behaviour(ct_suite).

-include_lib("stdlib/include/assert.hrl").
-include_lib("dns_erlang/include/dns.hrl").
-define(PIPELINE_ERROR_EVENT, [erldns, pipeline, error]).

-spec all() -> [ct_suite:ct_test_def()].
all() ->
    [
        terminate_removes_pt,
        sync,
        survives_cast_and_calls,
        configure_function_pipes,
        fail_to_configure_bad_function_pipes,
        configure_module_pipes_without_prepare,
        configure_module_pipes_with_bad_prepare,
        configure_module_pipes_with_prepare_returns_disable,
        configure_module_pipes_with_prepare,
        fail_to_configure_non_existing_module_pipe,
        configure_custom_pipeline,
        configure_module_pipe_without_call,
        pipe_returns_halt,
        pipe_returns_stop,
        pipe_returns_new_msg,
        pipe_returns_msg_and_opts,
        pipe_returns_unexpected_value,
        pipe_raises
    ].

-spec init_per_suite(ct_suite:ct_config()) -> ct_suite:ct_config().
init_per_suite(Config) ->
    application:ensure_all_started([telemetry]),
    ok = telemetry:attach(?MODULE, ?PIPELINE_ERROR_EVENT, fun ?MODULE:telemetry_handler/4, []),
    Config.

-spec end_per_suite(ct_suite:ct_config()) -> term().
end_per_suite(_) ->
    application:stop(telemetry).

-spec init_per_testcase(ct_suite:ct_testcase(), ct_suite:ct_config()) -> ct_suite:ct_config().
init_per_testcase(_, Config) ->
    erlang:process_flag(trap_exit, true),
    Config.

-spec end_per_testcase(ct_suite:ct_testcase(), ct_suite:ct_config()) -> term().
end_per_testcase(_, Config) ->
    Config.

%% Tests
terminate_removes_pt(_) ->
    application:set_env(erldns, packet_pipeline, []),
    ?assertMatch({ok, _}, erldns_pipeline_worker:start_link()),
    erlang:exit(whereis(erldns_pipeline_worker), normal),
    receive
        {'EXIT', _, normal} ->
            ok
    after 1000 -> ct:fail("erldns_pipeline did not die")
    end,
    ?assertEqual(undefined, persistent_term:get(erldns_pipeline, undefined)).

sync(_) ->
    application:set_env(erldns, packet_pipeline, []),
    ?assertMatch({ok, _}, erldns_pipeline_worker:start_link()),
    ?assertMatch({[], #{}}, persistent_term:get(erldns_pipeline, undefined)),
    application:set_env(erldns, packet_pipeline, [fun(A, _) -> A end]),
    ?assertEqual(ok, gen_server:call(erldns_pipeline_worker, sync)),
    ?assertMatch({[_], #{}}, persistent_term:get(erldns_pipeline, undefined)).

survives_cast_and_calls(_) ->
    application:set_env(erldns, packet_pipeline, []),
    ?assertMatch({ok, _}, erldns_pipeline_worker:start_link()),
    ?assertEqual(ok, gen_server:cast(erldns_pipeline_worker, whatever)),
    ?assertEqual(not_implemented, gen_server:call(erldns_pipeline_worker, whatever)),
    ?assert(is_pid(whereis(erldns_pipeline_worker))).

configure_function_pipes(_) ->
    application:set_env(erldns, packet_pipeline, [fun(A, _) -> A end]),
    ?assertMatch({ok, _}, erldns_pipeline_worker:start_link()),
    ?assertMatch({[_], #{}}, persistent_term:get(erldns_pipeline, undefined)).

fail_to_configure_bad_function_pipes(_) ->
    application:set_env(erldns, packet_pipeline, [fun(A, _, _) -> A end]),
    ?assertMatch(
        {error, {{badpipe, {function_pipe_has_wrong_arity, _}}, _}},
        erldns_pipeline_worker:start_link()
    ).

configure_module_pipes_with_prepare_returns_disable(_) ->
    meck:new(?FUNCTION_NAME, [non_strict]),
    meck:expect(?FUNCTION_NAME, call, fun(Msg, _) -> Msg end),
    meck:expect(?FUNCTION_NAME, prepare, fun(_) -> disabled end),
    application:set_env(erldns, packet_pipeline, [?FUNCTION_NAME]),
    ?assertMatch({ok, _}, erldns_pipeline_worker:start_link()),
    ?assertMatch({[], #{}}, persistent_term:get(erldns_pipeline, undefined)).

configure_module_pipes_with_prepare(_) ->
    meck:new(?FUNCTION_NAME, [non_strict]),
    meck:expect(?FUNCTION_NAME, call, fun(Msg, _) -> Msg end),
    meck:expect(?FUNCTION_NAME, prepare, fun(Opts) -> Opts end),
    application:set_env(erldns, packet_pipeline, [?FUNCTION_NAME]),
    ?assertMatch({ok, _}, erldns_pipeline_worker:start_link()),
    ?assertMatch({[_], #{}}, persistent_term:get(erldns_pipeline, undefined)).

configure_module_pipes_with_bad_prepare(_) ->
    meck:new(?FUNCTION_NAME, [non_strict]),
    meck:expect(?FUNCTION_NAME, call, fun(Msg, _) -> Msg end),
    meck:expect(?FUNCTION_NAME, prepare, fun(_) -> not_a_map end),
    application:set_env(erldns, packet_pipeline, [?FUNCTION_NAME]),
    ?assertMatch(
        {error, {{badpipe, {module_init_returned_non_map, ?FUNCTION_NAME}}, _}},
        erldns_pipeline_worker:start_link()
    ).

configure_module_pipes_without_prepare(_) ->
    meck:new(?FUNCTION_NAME, [non_strict]),
    meck:expect(?FUNCTION_NAME, call, fun(Msg, _) -> Msg end),
    application:set_env(erldns, packet_pipeline, [?FUNCTION_NAME]),
    ?assertMatch({ok, _}, erldns_pipeline_worker:start_link()),
    ?assertMatch({[_], #{}}, persistent_term:get(erldns_pipeline, undefined)).

fail_to_configure_non_existing_module_pipe(_) ->
    application:set_env(erldns, packet_pipeline, [?FUNCTION_NAME]),
    ?assertMatch({error, {{badpipe, {module, nofile}}, _}}, erldns_pipeline_worker:start_link()).

configure_custom_pipeline(_) ->
    meck:new(?FUNCTION_NAME, [non_strict]),
    meck:expect(?FUNCTION_NAME, call, fun(Msg, _) -> Msg end),
    meck:expect(?FUNCTION_NAME, prepare, fun(Opts) -> Opts end),
    Fun = fun(Msg, _) -> Msg end,
    erldns_pipeline:store_pipeline(?FUNCTION_NAME, [?FUNCTION_NAME, Fun]),
    Msg = example_msg(),
    ?assertMatch(Msg, erldns_pipeline:call_custom(Msg, def_opts(), ?FUNCTION_NAME)),
    erldns_pipeline:delete_pipeline(?FUNCTION_NAME).

configure_module_pipe_without_call(_) ->
    meck:new(?FUNCTION_NAME, [non_strict]),
    application:set_env(erldns, packet_pipeline, [?FUNCTION_NAME]),
    ?assertMatch(
        {error, {{badpipe, module_does_not_export_call}, _}},
        erldns_pipeline_worker:start_link()
    ).

pipe_returns_halt(_) ->
    Msg = example_msg(),
    Fun = fun(_, _) -> halt end,
    application:set_env(erldns, packet_pipeline, [Fun]),
    ?assertMatch({ok, _}, erldns_pipeline_worker:start_link()),
    ?assertMatch(halt, erldns_pipeline:call(Msg, def_opts())).

pipe_returns_stop(_) ->
    Msg = example_msg(),
    Fun = fun(M, _) -> {stop, M#dns_message{tc = true}} end,
    application:set_env(erldns, packet_pipeline, [Fun]),
    ?assertMatch({ok, _}, erldns_pipeline_worker:start_link()),
    ?assertMatch({[_], #{}}, persistent_term:get(erldns_pipeline, undefined)),
    ?assertMatch(#dns_message{tc = true}, erldns_pipeline:call(Msg, def_opts())).

pipe_returns_new_msg(_) ->
    Msg = example_msg(),
    Fun = fun(M, _) -> M#dns_message{tc = true} end,
    application:set_env(erldns, packet_pipeline, [Fun]),
    ?assertMatch({ok, _}, erldns_pipeline_worker:start_link()),
    ?assertMatch({[_], #{}}, persistent_term:get(erldns_pipeline, undefined)),
    ?assertMatch(#dns_message{tc = true}, erldns_pipeline:call(Msg, def_opts())).

pipe_returns_msg_and_opts(_) ->
    Msg = example_msg(),
    Fun = fun(M, O) -> {M#dns_message{tc = true}, O#{a => b}} end,
    application:set_env(erldns, packet_pipeline, [Fun]),
    ?assertMatch({ok, _}, erldns_pipeline_worker:start_link()),
    ?assertMatch({[_], #{}}, persistent_term:get(erldns_pipeline, undefined)),
    ?assertMatch(#dns_message{tc = true}, erldns_pipeline:call(Msg, def_opts())).

pipe_returns_unexpected_value(_) ->
    Msg = example_msg(),
    Fun = fun(_, _) -> #{} end,
    application:set_env(erldns, packet_pipeline, [Fun]),
    ?assertMatch({ok, _}, erldns_pipeline_worker:start_link()),
    ?assertMatch({[_], #{}}, persistent_term:get(erldns_pipeline, undefined)),
    ?assertMatch(#dns_message{tc = false}, erldns_pipeline:call(Msg, def_opts())),
    assert_telemetry_event().

pipe_raises(_) ->
    Msg = example_msg(),
    Fun = fun(_, _) -> erlang:error(an_error) end,
    application:set_env(erldns, packet_pipeline, [Fun]),
    ?assertMatch({ok, _}, erldns_pipeline_worker:start_link()),
    ?assertMatch({[_], #{}}, persistent_term:get(erldns_pipeline, undefined)),
    ?assertMatch(#dns_message{tc = false}, erldns_pipeline:call(Msg, def_opts())),
    assert_telemetry_event().

telemetry_handler(EventName, _, _, _) ->
    ct:pal("EventName ~p~n", [EventName]),
    self() ! EventName.

assert_telemetry_event() ->
    receive
        ?PIPELINE_ERROR_EVENT ->
            ok
    after 1000 ->
        ct:fail("Telemetry event not triggered: questions")
    end.

def_opts() ->
    erldns_pipeline:def_opts().

example_msg() ->
    Qs = [#dns_query{name = ~"example.com", type = ?DNS_TYPE_A}],
    #dns_message{qc = 1, questions = Qs}.
