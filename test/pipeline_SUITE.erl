-module(pipeline_SUITE).
-compile([export_all, nowarn_export_all]).

-behaviour(ct_suite).

-include_lib("stdlib/include/assert.hrl").
-include_lib("dns_erlang/include/dns.hrl").
-define(PIPE_ERROR_EVENT, [erldns, pipeline, error]).

-spec all() -> [ct_suite:ct_test_def()].
all() ->
    [
        {group, general},
        {group, pipe_calls},
        {group, dependencies},
        {group, is_pipe_configured},
        {group, pipeline_suspension},
        {group, suspension_integration}
    ].

-spec groups() -> [ct_suite:ct_group_def()].
groups() ->
    [
        {general, [sequence], [
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
            configure_module_pipe_without_call
        ]},
        {pipe_calls, [parallel], [
            pipe_returns_halt,
            pipe_returns_stop,
            pipe_returns_new_msg,
            pipe_returns_msg_and_opts,
            pipe_returns_unexpected_value,
            pipe_raises
        ]},
        {dependencies, [sequence], [
            simple_prerequisite_satisfied,
            simple_dependency_satisfied,
            prerequisite_order_violated,
            dependency_order_violated,
            multiple_dependencies_satisfied,
            transitive_dependencies_satisfied,
            backward_compatible_no_deps,
            mixed_spec_formats
        ]},
        {is_pipe_configured, [sequence], [
            is_pipe_configured_module_in_main_pipeline,
            is_pipe_configured_function_in_main_pipeline,
            is_pipe_configured_not_in_main_pipeline,
            is_pipe_configured_in_custom_pipeline,
            is_pipe_configured_nonexistent_pipeline
        ]},
        {pipeline_suspension, [parallel], [
            pipe_returns_suspend,
            pipe_suspend_resumes_remaining_pipeline,
            continuation_execute_work,
            continuation_resume,
            continuation_execute_and_resume
        ]},
        {suspension_integration, [parallel], [
            udp_basic_pipeline_works,
            udp_suspend_async_pool_integration,
            udp_suspend_with_remaining_pipeline,
            tcp_basic_pipeline_works,
            tcp_suspend_sync_integration,
            tcp_suspend_with_remaining_pipeline,
            suspend_halt_from_async_fun,
            suspend_chain_limited,
            suspend_async_returns_msg_with_opts,
            suspend_async_returns_stop,
            suspend_async_returns_invalid,
            suspend_async_raises_exception
        ]}
    ].

-spec init_per_suite(ct_suite:ct_config()) -> ct_suite:ct_config().
init_per_suite(Config) ->
    application:ensure_all_started([telemetry]),
    ok = telemetry:attach(?MODULE, ?PIPE_ERROR_EVENT, fun ?MODULE:telemetry_handler/4, []),
    Config.

-spec init_per_group(atom(), ct_suite:ct_config()) -> ct_suite:ct_config().
init_per_group(suspension_integration, Config) ->
    [{integration, true} | Config];
init_per_group(_, Config) ->
    Config.

-spec end_per_group(atom(), ct_suite:ct_config()) -> term().
end_per_group(suspension_integration, Config) ->
    case proplists:get_value(peer_started, Config, false) of
        true -> app_helper:stop(Config);
        false -> ok
    end,
    Config;
end_per_group(_, Config) ->
    Config.

-spec end_per_suite(ct_suite:ct_config()) -> term().
end_per_suite(_) ->
    application:stop(telemetry).

-spec init_per_testcase(ct_suite:ct_testcase(), ct_suite:ct_config()) -> ct_suite:ct_config().
init_per_testcase(_, Config) ->
    erlang:process_flag(trap_exit, true),
    Config.

-spec end_per_testcase(ct_suite:ct_testcase(), ct_suite:ct_config()) -> term().
end_per_testcase(TC, Config) ->
    erldns_pipeline:delete_pipeline(TC),
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
    ?assertMatch(Msg, erldns_pipeline:call_custom(Msg, def_opts(), ?FUNCTION_NAME)).

configure_module_pipe_without_call(_) ->
    meck:new(?FUNCTION_NAME, [non_strict]),
    application:set_env(erldns, packet_pipeline, [?FUNCTION_NAME]),
    ?assertMatch(
        {error, {{badpipe, {module_does_not_export_call, _}}, _}},
        erldns_pipeline_worker:start_link()
    ).

pipe_returns_halt(_) ->
    Msg = example_msg(),
    Fun = fun(_, _) -> halt end,
    erldns_pipeline:store_pipeline(?FUNCTION_NAME, [Fun]),
    ?assertMatch(halt, erldns_pipeline:call_custom(Msg, def_opts(), ?FUNCTION_NAME)).

pipe_returns_stop(_) ->
    Msg = example_msg(),
    Fun = fun(M, _) -> {stop, M#dns_message{tc = true}} end,
    erldns_pipeline:store_pipeline(?FUNCTION_NAME, [Fun]),
    ?assertMatch({[_], #{}}, persistent_term:get(?FUNCTION_NAME, undefined)),
    ?assertMatch(
        #dns_message{tc = true}, erldns_pipeline:call_custom(Msg, def_opts(), ?FUNCTION_NAME)
    ).

pipe_returns_new_msg(_) ->
    Msg = example_msg(),
    Fun = fun(M, _) -> M#dns_message{tc = true} end,
    erldns_pipeline:store_pipeline(?FUNCTION_NAME, [Fun]),
    ?assertMatch({[_], #{}}, persistent_term:get(?FUNCTION_NAME, undefined)),
    ?assertMatch(
        #dns_message{tc = true}, erldns_pipeline:call_custom(Msg, def_opts(), ?FUNCTION_NAME)
    ).

pipe_returns_msg_and_opts(_) ->
    Msg = example_msg(),
    Fun = fun(M, O) -> {M#dns_message{tc = true}, O#{a => b}} end,
    erldns_pipeline:store_pipeline(?FUNCTION_NAME, [Fun]),
    ?assertMatch({[_], #{}}, persistent_term:get(?FUNCTION_NAME, undefined)),
    ?assertMatch(
        #dns_message{tc = true}, erldns_pipeline:call_custom(Msg, def_opts(), ?FUNCTION_NAME)
    ).

pipe_returns_unexpected_value(_) ->
    Msg = example_msg(),
    Fun = fun(_, _) -> #{} end,
    erldns_pipeline:store_pipeline(?FUNCTION_NAME, [Fun]),
    ?assertMatch({[_], #{}}, persistent_term:get(?FUNCTION_NAME, undefined)),
    ?assertMatch(
        #dns_message{tc = false}, erldns_pipeline:call_custom(Msg, def_opts(), ?FUNCTION_NAME)
    ),
    assert_telemetry_event(unexpected).

pipe_raises(_) ->
    Msg = example_msg(),
    Fun = fun(_, _) -> erlang:error(an_error) end,
    erldns_pipeline:store_pipeline(?FUNCTION_NAME, [Fun]),
    ?assertMatch({[_], #{}}, persistent_term:get(?FUNCTION_NAME, undefined)),
    ?assertMatch(
        #dns_message{tc = false}, erldns_pipeline:call_custom(Msg, def_opts(), ?FUNCTION_NAME)
    ),
    assert_telemetry_event(exception).

simple_prerequisite_satisfied(_) ->
    % Create two mock modules: B depends on A (via callback)
    meck:new(pipe_a, [non_strict]),
    meck:new(pipe_b, [non_strict]),
    meck:expect(pipe_a, call, fun(Msg, _) -> Msg end),
    meck:expect(pipe_b, call, fun(Msg, _) -> Msg end),
    meck:expect(pipe_a, deps, fun() -> #{dependents => [pipe_b]} end),
    % Configure pipeline with correct order: A before B
    Pipes = [pipe_a, pipe_b],
    erldns_pipeline:store_pipeline(?FUNCTION_NAME, Pipes),
    Msg = example_msg(),
    Result = erldns_pipeline:call_custom(Msg, #{}, ?FUNCTION_NAME),
    ?assertMatch(#dns_message{}, Result),
    meck:unload([pipe_a, pipe_b]).

simple_dependency_satisfied(_) ->
    % Create two mock modules: B depends on A (via callback)
    meck:new(pipe_a, [non_strict]),
    meck:new(pipe_b, [non_strict]),
    meck:expect(pipe_a, call, fun(Msg, _) -> Msg end),
    meck:expect(pipe_b, call, fun(Msg, _) -> Msg end),
    meck:expect(pipe_b, deps, fun() -> #{prerequisites => [pipe_a]} end),
    % Configure pipeline with correct order: A before B
    Pipes = [pipe_a, pipe_b],
    erldns_pipeline:store_pipeline(?FUNCTION_NAME, Pipes),
    Msg = example_msg(),
    Result = erldns_pipeline:call_custom(Msg, #{}, ?FUNCTION_NAME),
    ?assertMatch(#dns_message{}, Result),
    meck:unload([pipe_a, pipe_b]).

prerequisite_order_violated(_) ->
    % Create two mock modules: B depends on A but A comes after B
    meck:new(pipe_a, [non_strict]),
    meck:new(pipe_b, [non_strict]),
    meck:expect(pipe_a, call, fun(Msg, _) -> Msg end),
    meck:expect(pipe_b, call, fun(Msg, _) -> Msg end),
    meck:expect(pipe_b, deps, fun() -> #{prerequisites => [pipe_a]} end),
    % Configure pipeline with WRONG order: B before A (violates dependency)
    Pipes = [pipe_b, pipe_a],
    % Should raise badpipe error with unsatisfied_dependency
    ?assertError(
        {badpipe, {unsatisfied_dependency, #{pipe := pipe_b, requires := pipe_a}}},
        erldns_pipeline:store_pipeline(?FUNCTION_NAME, Pipes)
    ),
    meck:unload([pipe_a, pipe_b]).

dependency_order_violated(_) ->
    % Create two mock modules: B depends on A but A comes after B
    meck:new(pipe_a, [non_strict]),
    meck:new(pipe_b, [non_strict]),
    meck:expect(pipe_a, call, fun(Msg, _) -> Msg end),
    meck:expect(pipe_b, call, fun(Msg, _) -> Msg end),
    meck:expect(pipe_a, deps, fun() -> #{dependents => [pipe_b]} end),
    % Configure pipeline with WRONG order: B before A (violates dependency)
    Pipes = [pipe_b, pipe_a],
    % Should raise badpipe error with unsatisfied_dependency
    ?assertError(
        {badpipe, {unsatisfied_dependency, #{pipe := pipe_a, requires := pipe_b}}},
        erldns_pipeline:store_pipeline(?FUNCTION_NAME, Pipes)
    ),
    meck:unload([pipe_a, pipe_b]).

multiple_dependencies_satisfied(_) ->
    % Create three mock modules: C depends on both A and B (via callback)
    meck:new(pipe_a, [non_strict]),
    meck:new(pipe_b, [non_strict]),
    meck:new(pipe_c, [non_strict]),
    meck:expect(pipe_a, call, fun(Msg, _) -> Msg end),
    meck:expect(pipe_b, call, fun(Msg, _) -> Msg end),
    meck:expect(pipe_c, call, fun(Msg, _) -> Msg end),
    meck:expect(pipe_c, deps, fun() -> #{prerequisites => [pipe_a, pipe_b]} end),
    % Configure pipeline with correct order: A and B before C
    Pipes = [pipe_a, pipe_b, pipe_c],
    erldns_pipeline:store_pipeline(?FUNCTION_NAME, Pipes),
    Msg = example_msg(),
    Result = erldns_pipeline:call_custom(Msg, #{}, ?FUNCTION_NAME),
    ?assertMatch(#dns_message{}, Result),
    meck:unload([pipe_a, pipe_b, pipe_c]).

transitive_dependencies_satisfied(_) ->
    % Create three mock modules: C depends on B, B depends on A (via callbacks)
    meck:new(pipe_a, [non_strict]),
    meck:new(pipe_b, [non_strict]),
    meck:new(pipe_c, [non_strict]),
    meck:expect(pipe_a, call, fun(Msg, _) -> Msg end),
    meck:expect(pipe_b, call, fun(Msg, _) -> Msg end),
    meck:expect(pipe_c, call, fun(Msg, _) -> Msg end),
    meck:expect(pipe_b, deps, fun() -> #{prerequisites => [pipe_a]} end),
    meck:expect(pipe_c, deps, fun() -> #{prerequisites => [pipe_b]} end),
    % Configure pipeline with correct order: A before B before C
    Pipes = [pipe_a, pipe_b, pipe_c],
    erldns_pipeline:store_pipeline(?FUNCTION_NAME, Pipes),
    Msg = example_msg(),
    Result = erldns_pipeline:call_custom(Msg, #{}, ?FUNCTION_NAME),
    ?assertMatch(#dns_message{}, Result),
    meck:unload([pipe_a, pipe_b, pipe_c]).

backward_compatible_no_deps(_) ->
    % Verify that pipes without deps/0 callback still work
    meck:new(pipe_a, [non_strict]),
    meck:new(pipe_b, [non_strict]),
    meck:expect(pipe_a, call, fun(Msg, _) -> Msg end),
    meck:expect(pipe_b, call, fun(Msg, _) -> Msg end),
    % Pipes without deps callback
    Pipes = [pipe_a, pipe_b],
    erldns_pipeline:store_pipeline(?FUNCTION_NAME, Pipes),
    Msg = example_msg(),
    Result = erldns_pipeline:call_custom(Msg, #{}, ?FUNCTION_NAME),
    ?assertMatch(#dns_message{}, Result),
    meck:unload([pipe_a, pipe_b]).

mixed_spec_formats(_) ->
    % Mix pipes with and without deps callback
    meck:new(pipe_a, [non_strict]),
    meck:new(pipe_b, [non_strict]),
    meck:new(pipe_c, [non_strict]),
    meck:expect(pipe_a, call, fun(Msg, _) -> Msg end),
    meck:expect(pipe_b, call, fun(Msg, _) -> Msg end),
    meck:expect(pipe_c, call, fun(Msg, _) -> Msg end),
    meck:expect(pipe_c, deps, fun() -> #{prerequisites => [pipe_b]} end),
    Pipes = [pipe_a, pipe_b, pipe_c],
    erldns_pipeline:store_pipeline(?FUNCTION_NAME, Pipes),
    Msg = example_msg(),
    Result = erldns_pipeline:call_custom(Msg, #{}, ?FUNCTION_NAME),
    ?assertMatch(#dns_message{}, Result),
    meck:unload([pipe_a, pipe_b, pipe_c]).

telemetry_handler(EventName, _, Metadata, _) ->
    ct:pal("EventName ~p~n", [EventName]),
    self() ! {EventName, Metadata}.

assert_telemetry_event(Type) ->
    receive
        {?PIPE_ERROR_EVENT, #{kind := _, reason := _, stacktrace := _}} when Type =:= exception ->
            ok;
        {?PIPE_ERROR_EVENT, #{reason := _}} when Type =:= unexpected ->
            ok
    after 1000 ->
        ct:fail("Telemetry event not triggered: error")
    end.

def_opts() ->
    erldns_pipeline:def_opts().

example_msg() ->
    Qs = [#dns_query{name = ~"example.com", type = ?DNS_TYPE_A}],
    #dns_message{qc = 1, questions = Qs}.

%% Tests for is_pipe_configured

is_pipe_configured_module_in_main_pipeline(_) ->
    % Create a mock module pipe and configure the main pipeline
    meck:new(pipe_test_module, [non_strict]),
    meck:expect(pipe_test_module, call, fun(Msg, _) -> Msg end),
    application:set_env(erldns, packet_pipeline, [pipe_test_module]),
    ?assertMatch({ok, _}, erldns_pipeline_worker:start_link()),
    % Check that the module pipe is configured
    ?assert(erldns_pipeline:is_pipe_configured(pipe_test_module)),
    meck:unload(pipe_test_module).

is_pipe_configured_function_in_main_pipeline(_) ->
    % Create a function pipe and configure the main pipeline
    Fun = fun(Msg, _) -> Msg end,
    application:set_env(erldns, packet_pipeline, [Fun]),
    ?assertMatch({ok, _}, erldns_pipeline_worker:start_link()),
    % Check that the function pipe is configured
    ?assert(erldns_pipeline:is_pipe_configured(Fun)),
    % Check that the exact function reference matters
    OtherFun = fun(Msg, _) -> Msg end,
    ?assertNot(erldns_pipeline:is_pipe_configured(OtherFun)).

is_pipe_configured_not_in_main_pipeline(_) ->
    % Configure the main pipeline with one module
    meck:new(pipe_present, [non_strict]),
    meck:expect(pipe_present, call, fun(Msg, _) -> Msg end),
    application:set_env(erldns, packet_pipeline, [pipe_present]),
    ?assertMatch({ok, _}, erldns_pipeline_worker:start_link()),
    % Check that a different module is not configured
    ?assertNot(erldns_pipeline:is_pipe_configured(pipe_absent)),
    meck:unload(pipe_present).

is_pipe_configured_in_custom_pipeline(_) ->
    % Create mock modules and configure a custom pipeline
    meck:new(pipe_custom_a, [non_strict]),
    meck:new(pipe_custom_b, [non_strict]),
    meck:expect(pipe_custom_a, call, fun(Msg, _) -> Msg end),
    meck:expect(pipe_custom_b, call, fun(Msg, _) -> Msg end),
    erldns_pipeline:store_pipeline(?FUNCTION_NAME, [pipe_custom_a, pipe_custom_b]),
    % Check that both pipes are configured in the custom pipeline
    ?assert(erldns_pipeline:is_pipe_configured(pipe_custom_a, ?FUNCTION_NAME)),
    ?assert(erldns_pipeline:is_pipe_configured(pipe_custom_b, ?FUNCTION_NAME)),
    % Check that a different module is not configured
    ?assertNot(erldns_pipeline:is_pipe_configured(pipe_custom_c, ?FUNCTION_NAME)),
    meck:unload([pipe_custom_a, pipe_custom_b]).

is_pipe_configured_nonexistent_pipeline(_) ->
    % Check that querying a nonexistent pipeline returns false
    ?assertNot(erldns_pipeline:is_pipe_configured(any_any_pipe, very_nonexistent_pipeline)).

%% ===================================================================
%% Pipeline Suspension Tests
%% ===================================================================

%% Verify pipeline returns {suspend, Continuation} when pipe suspends.
pipe_returns_suspend(_) ->
    Msg = example_msg(),
    AsyncFun = fun(M, _) -> M#dns_message{aa = true} end,
    SuspendFun = fun(M, Opts) -> {suspend, M, Opts, AsyncFun} end,
    erldns_pipeline:store_pipeline(?FUNCTION_NAME, [SuspendFun]),
    Result = erldns_pipeline:call_custom(Msg, def_opts(), ?FUNCTION_NAME),
    ?assertMatch({suspend, _}, Result).

%% Verify suspension captures remaining pipeline and resuming executes them.
pipe_suspend_resumes_remaining_pipeline(_) ->
    Msg = example_msg(),
    AsyncFun = fun(M, _) -> M#dns_message{aa = true} end,
    SecondPipe = fun(M, _) -> M#dns_message{tc = true} end,
    SuspendFun = fun(M, Opts) -> {suspend, M, Opts, AsyncFun} end,
    erldns_pipeline:store_pipeline(?FUNCTION_NAME, [SuspendFun, SecondPipe]),
    {suspend, Cont} = erldns_pipeline:call_custom(Msg, def_opts(), ?FUNCTION_NAME),
    Result = erldns_pipeline:resume_pipeline(Cont),
    ?assertMatch(#dns_message{}, Result),
    ?assertEqual(true, Result#dns_message.aa),
    ?assertEqual(true, Result#dns_message.tc).

%% Verify execute_work runs the work function and returns updated continuation.
continuation_execute_work(_) ->
    Msg = example_msg(),
    Context = #{multiplier => 2},
    AsyncFun = fun(M, _) ->
        #{multiplier := N} = Context,
        M#dns_message{anc = N * 5}
    end,
    SuspendFun = fun(M, Opts) -> {suspend, M, Opts, AsyncFun} end,
    SecondPipe = fun(M, _) -> M#dns_message{tc = true} end,
    erldns_pipeline:store_pipeline(?FUNCTION_NAME, [SuspendFun, SecondPipe]),
    {suspend, Cont} = erldns_pipeline:call_custom(Msg, def_opts(), ?FUNCTION_NAME),
    ResultCont = erldns_pipeline:execute_work(Cont),
    ?assertNotEqual(halt, ResultCont),
    ResultMsg = erldns_pipeline:get_continuation_message(ResultCont),
    ?assertEqual(false, ResultMsg#dns_message.tc),
    ?assertEqual(10, ResultMsg#dns_message.anc).

%% Verify resume_pipeline continues executing remaining pipeline stages.
continuation_resume(_) ->
    Msg = example_msg(),
    AsyncFun = fun(M, _) -> M#dns_message{aa = true} end,
    SuspendPipe = fun(M, Opts) -> {suspend, M, Opts, AsyncFun} end,
    FinalPipe = fun(M, _) -> M#dns_message{tc = true} end,
    erldns_pipeline:store_pipeline(?FUNCTION_NAME, [SuspendPipe, FinalPipe]),
    {suspend, Cont} = erldns_pipeline:call_custom(Msg, def_opts(), ?FUNCTION_NAME),
    % Execute work, then resume remaining pipeline
    Cont1 = erldns_pipeline:execute_work(Cont),
    Result = erldns_pipeline:resume_pipeline(Cont1),
    ?assertEqual(true, Result#dns_message.aa),
    ?assertEqual(true, Result#dns_message.tc).

%% Verify resume_pipeline combines work execution and pipeline resumption.
continuation_execute_and_resume(_) ->
    Msg = example_msg(),
    AsyncFun = fun(M, _) -> M#dns_message{aa = true} end,
    SuspendPipe = fun(M, Opts) ->
        {suspend, M, Opts, AsyncFun}
    end,
    FinalPipe = fun(M, _) -> M#dns_message{tc = true} end,
    erldns_pipeline:store_pipeline(?FUNCTION_NAME, [SuspendPipe, FinalPipe]),
    {suspend, Cont} = erldns_pipeline:call_custom(Msg, def_opts(), ?FUNCTION_NAME),
    Result = erldns_pipeline:resume_pipeline(Cont),
    ?assertEqual(true, Result#dns_message.aa),
    ?assertEqual(true, Result#dns_message.tc).

%% ===================================================================
%% Suspension Integration Tests
%% ===================================================================
%% These tests use a peer node with actual UDP/TCP listeners to verify
%% the complete suspension flow through async pool and transport layers.

%% Verify basic UDP pipeline works (sanity check before testing suspension).
udp_basic_pipeline_works(Config) ->
    #{port := Port} = start_integration_peer(
        Config, ?FUNCTION_NAME, udp, [fun marking_pipe/2]
    ),
    Packet = example_packet(),
    {ok, Socket} = gen_udp:open(0, [binary, {active, false}]),
    ok = gen_udp:send(Socket, {127, 0, 0, 1}, Port, Packet),
    {ok, {_, _, ResponseBin}} = gen_udp:recv(Socket, 0, 5000),
    Response = dns:decode_message(ResponseBin),
    %% marking_pipe sets tc=true
    ?assertEqual(true, Response#dns_message.tc),
    gen_udp:close(Socket).

%% Verify UDP suspension works end-to-end: pipe suspends, async pool executes
%% work, UDP worker receives {async_done, Continuation} and sends response.
udp_suspend_async_pool_integration(Config) ->
    #{port := Port} = start_integration_peer(
        Config, ?FUNCTION_NAME, udp, [fun suspending_pipe/2]
    ),
    Packet = example_packet(),
    {ok, Socket} = gen_udp:open(0, [binary, {active, false}]),
    ok = gen_udp:send(Socket, {127, 0, 0, 1}, Port, Packet),
    {ok, {_, _, ResponseBin}} = gen_udp:recv(Socket, 0, 5000),
    Response = dns:decode_message(ResponseBin),
    %% AsyncFun sets aa=true
    ?assertEqual(true, Response#dns_message.aa),
    gen_udp:close(Socket).

%% Verify UDP suspension with remaining pipeline stages after async work.
udp_suspend_with_remaining_pipeline(Config) ->
    #{port := Port} = start_integration_peer(
        Config, ?FUNCTION_NAME, udp, [fun suspending_pipe/2, fun marking_pipe/2]
    ),
    Packet = example_packet(),
    {ok, Socket} = gen_udp:open(0, [binary, {active, false}]),
    ok = gen_udp:send(Socket, {127, 0, 0, 1}, Port, Packet),
    {ok, {_, _, ResponseBin}} = gen_udp:recv(Socket, 0, 5000),
    Response = dns:decode_message(ResponseBin),
    %% AsyncFun sets aa=true, then marking_pipe sets tc=true
    ?assertEqual(true, Response#dns_message.aa),
    ?assertEqual(true, Response#dns_message.tc),
    gen_udp:close(Socket).

%% Verify basic TCP pipeline works (sanity check before testing suspension).
tcp_basic_pipeline_works(Config) ->
    #{port := Port} = start_integration_peer(
        Config, ?FUNCTION_NAME, tcp, [fun marking_pipe/2]
    ),
    Packet = example_packet(),
    {ok, Socket} = gen_tcp:connect({127, 0, 0, 1}, Port, [binary, {active, false}]),
    ok = gen_tcp:send(Socket, [<<(byte_size(Packet)):16>>, Packet]),
    {ok, <<Len:16, ResponseBin:Len/binary>>} = gen_tcp:recv(Socket, 0, 5000),
    Response = dns:decode_message(ResponseBin),
    %% marking_pipe sets tc=true
    ?assertEqual(true, Response#dns_message.tc),
    gen_tcp:close(Socket).

%% Verify TCP suspension works end-to-end: pipe suspends, TCP calls
%% resume_pipeline synchronously, response is sent.
tcp_suspend_sync_integration(Config) ->
    #{port := Port} = start_integration_peer(
        Config, ?FUNCTION_NAME, tcp, [fun suspending_pipe/2]
    ),
    Packet = example_packet(),
    {ok, Socket} = gen_tcp:connect({127, 0, 0, 1}, Port, [binary, {active, false}]),
    ok = gen_tcp:send(Socket, [<<(byte_size(Packet)):16>>, Packet]),
    {ok, <<Len:16, ResponseBin:Len/binary>>} = gen_tcp:recv(Socket, 0, 5000),
    Response = dns:decode_message(ResponseBin),
    %% AsyncFun sets aa=true
    ?assertEqual(true, Response#dns_message.aa),
    gen_tcp:close(Socket).

%% Verify TCP suspension with remaining pipeline stages after async work.
tcp_suspend_with_remaining_pipeline(Config) ->
    #{port := Port} = start_integration_peer(
        Config, ?FUNCTION_NAME, tcp, [fun suspending_pipe/2, fun marking_pipe/2]
    ),
    Packet = example_packet(),
    {ok, Socket} = gen_tcp:connect({127, 0, 0, 1}, Port, [binary, {active, false}]),
    ok = gen_tcp:send(Socket, [<<(byte_size(Packet)):16>>, Packet]),
    {ok, <<Len:16, ResponseBin:Len/binary>>} = gen_tcp:recv(Socket, 0, 5000),
    Response = dns:decode_message(ResponseBin),
    %% AsyncFun sets aa=true, then marking_pipe sets tc=true
    ?assertEqual(true, Response#dns_message.aa),
    ?assertEqual(true, Response#dns_message.tc),
    gen_tcp:close(Socket).

%% Verify halt returned from async function stops processing without response.
suspend_halt_from_async_fun(Config) ->
    #{port := Port} = start_integration_peer(
        Config, ?FUNCTION_NAME, udp, [fun halting_suspend_pipe/2, fun marking_pipe/2]
    ),
    Packet = example_packet(),
    {ok, Socket} = gen_udp:open(0, [binary, {active, false}]),
    ok = gen_udp:send(Socket, {127, 0, 0, 1}, Port, Packet),
    %% Should not receive a response since async fun returns halt
    {error, timeout} = gen_udp:recv(Socket, 0, 500),
    gen_udp:close(Socket).

%% Verify chain of suspends is limited to prevent infinite loops.
suspend_chain_limited(Config) ->
    #{port := Port} = start_integration_peer(
        Config, ?FUNCTION_NAME, udp, [fun chain_suspend_pipe/2]
    ),
    Packet = example_packet(),
    {ok, Socket} = gen_udp:open(0, [binary, {active, false}]),
    ok = gen_udp:send(Socket, {127, 0, 0, 1}, Port, Packet),
    %% Chain suspends 4 times, but limit is 3, so it should halt (no response)
    {error, timeout} = gen_udp:recv(Socket, 0, 500),
    gen_udp:close(Socket).

%% Verify async fun can return {Message, Opts} to update both.
suspend_async_returns_msg_with_opts(Config) ->
    #{port := Port} = start_integration_peer(
        Config, ?FUNCTION_NAME, udp, [fun suspend_with_opts_pipe/2, fun opts_checking_pipe/2]
    ),
    Packet = example_packet(),
    {ok, Socket} = gen_udp:open(0, [binary, {active, false}]),
    ok = gen_udp:send(Socket, {127, 0, 0, 1}, Port, Packet),
    {ok, {_, _, ResponseBin}} = gen_udp:recv(Socket, 0, 5000),
    Response = dns:decode_message(ResponseBin),
    %% AsyncFun sets aa=true, opts_checking_pipe sees custom_opt and sets tc=true
    ?assertEqual(true, Response#dns_message.aa),
    ?assertEqual(true, Response#dns_message.tc),
    gen_udp:close(Socket).

%% Verify async fun returning {stop, Message} skips remaining pipeline.
suspend_async_returns_stop(Config) ->
    #{port := Port} = start_integration_peer(
        Config, ?FUNCTION_NAME, udp, [fun suspend_stop_pipe/2, fun marking_pipe/2]
    ),
    Packet = example_packet(),
    {ok, Socket} = gen_udp:open(0, [binary, {active, false}]),
    ok = gen_udp:send(Socket, {127, 0, 0, 1}, Port, Packet),
    {ok, {_, _, ResponseBin}} = gen_udp:recv(Socket, 0, 5000),
    Response = dns:decode_message(ResponseBin),
    %% AsyncFun sets aa=true and returns stop, marking_pipe should NOT run
    ?assertEqual(true, Response#dns_message.aa),
    ?assertEqual(false, Response#dns_message.tc),
    gen_udp:close(Socket).

%% Verify async fun returning invalid value logs error and continues.
suspend_async_returns_invalid(Config) ->
    #{port := Port} = start_integration_peer(
        Config, ?FUNCTION_NAME, udp, [fun suspend_invalid_pipe/2, fun marking_pipe/2]
    ),
    Packet = example_packet(),
    {ok, Socket} = gen_udp:open(0, [binary, {active, false}]),
    ok = gen_udp:send(Socket, {127, 0, 0, 1}, Port, Packet),
    {ok, {_, _, ResponseBin}} = gen_udp:recv(Socket, 0, 5000),
    Response = dns:decode_message(ResponseBin),
    %% AsyncFun returns invalid, original message used, marking_pipe still runs
    ?assertEqual(false, Response#dns_message.aa),
    ?assertEqual(true, Response#dns_message.tc),
    gen_udp:close(Socket).

%% Verify async fun raising exception logs error and continues.
suspend_async_raises_exception(Config) ->
    #{port := Port} = start_integration_peer(
        Config, ?FUNCTION_NAME, udp, [fun suspend_exception_pipe/2, fun marking_pipe/2]
    ),
    Packet = example_packet(),
    {ok, Socket} = gen_udp:open(0, [binary, {active, false}]),
    ok = gen_udp:send(Socket, {127, 0, 0, 1}, Port, Packet),
    {ok, {_, _, ResponseBin}} = gen_udp:recv(Socket, 0, 5000),
    Response = dns:decode_message(ResponseBin),
    %% AsyncFun raises, original message used, marking_pipe still runs
    ?assertEqual(false, Response#dns_message.aa),
    ?assertEqual(true, Response#dns_message.tc),
    gen_udp:close(Socket).

%% ===================================================================
%% Integration Test Helpers
%% ===================================================================

start_integration_peer(Config, Name, Transport, Pipeline) ->
    ListenerOpts = #{ingress_request_timeout => 5000},
    AppConfig = [
        {erldns, [
            {listeners, [
                #{
                    name => Name,
                    transport => Transport,
                    port => 0,
                    opts => ListenerOpts
                }
            ]},
            {packet_pipeline, Pipeline}
        ]}
    ],
    Config1 = app_helper:start_erldns(Config, AppConfig),
    Node = app_helper:get_node(Config1),
    ct:sleep(100),
    Port = app_helper:get_configured_port(Config1, Name, Transport),
    ct:pal("Integration test ~p:~p on port ~p", [Name, Transport, Port]),
    #{port => Port, node => Node, config => Config1}.

%% A pipe that suspends with an async function that sets aa=true
suspending_pipe(Msg, Opts) ->
    AsyncFun = fun(M, _) -> M#dns_message{aa = true} end,
    {suspend, Msg, Opts, AsyncFun}.

%% A pipe that sets tc=true (used after suspension to verify remaining pipeline)
marking_pipe(Msg, _Opts) ->
    Msg#dns_message{tc = true}.

%% A pipe that suspends but the async function returns halt
halting_suspend_pipe(Msg, Opts) ->
    AsyncFun = fun(_, _) -> halt end,
    {suspend, Msg, Opts, AsyncFun}.

%% A pipe that creates a chain of suspends (for testing loop limit)
%% The limit is 3, so this creates 4 nested suspends to exceed it.
chain_suspend_pipe(Msg, Opts) ->
    %% Level 4: innermost
    Level4 = fun(M, _) -> M#dns_message{aa = true} end,
    %% Level 3
    Level3 = fun(M, O) -> {suspend, M, O, Level4} end,
    %% Level 2
    Level2 = fun(M, O) -> {suspend, M, O, Level3} end,
    %% Level 1
    Level1 = fun(M, O) -> {suspend, M, O, Level2} end,
    %% Level 0: initial suspend
    {suspend, Msg, Opts, Level1}.

%% A pipe that suspends with async fun returning {Message, Opts}
suspend_with_opts_pipe(Msg, Opts) ->
    AsyncFun = fun(M, O) ->
        {M#dns_message{aa = true}, O#{custom_opt => true}}
    end,
    {suspend, Msg, Opts, AsyncFun}.

%% A pipe that checks for custom_opt and sets tc=true if present
opts_checking_pipe(Msg, Opts) ->
    case maps:get(custom_opt, Opts, false) of
        true -> Msg#dns_message{tc = true};
        false -> Msg
    end.

%% A pipe that suspends with async fun returning {stop, Message}
suspend_stop_pipe(Msg, Opts) ->
    AsyncFun = fun(M, _) -> {stop, M#dns_message{aa = true}} end,
    {suspend, Msg, Opts, AsyncFun}.

%% A pipe that suspends with async fun returning invalid value
suspend_invalid_pipe(Msg, Opts) ->
    AsyncFun = fun(_, _) -> {invalid, return, value} end,
    {suspend, Msg, Opts, AsyncFun}.

%% A pipe that suspends with async fun that raises an exception
suspend_exception_pipe(Msg, Opts) ->
    AsyncFun = fun(_, _) -> error(intentional_test_error) end,
    {suspend, Msg, Opts, AsyncFun}.

%% Create an example DNS query packet (matches listeners_SUITE:packet())
example_packet() ->
    Q = #dns_query{name = ~"example.com", type = ?DNS_TYPE_A},
    Msg = #dns_message{qc = 1, questions = [Q]},
    dns:encode_message(Msg).
