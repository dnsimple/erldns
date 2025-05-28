-module(pipeline_SUITE).
-compile([export_all, nowarn_export_all]).

-behaviour(ct_suite).

-include_lib("stdlib/include/assert.hrl").
-include_lib("dns_erlang/include/dns.hrl").

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
        configure_module_pipe_without_call,
        pipe_returns_stop,
        pipe_returns_new_msg,
        pipe_returns_msg_and_opts,
        pipe_returns_unexpected_value,
        pipe_raises
    ].

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
    ?assertMatch({ok, _}, erldns_pipeline:start_link()),
    erlang:exit(whereis(erldns_pipeline), normal),
    receive
        {'EXIT', _, normal} ->
            ok
    after 1000 -> ct:fail("erldns_pipeline did not die")
    end,
    ?assertEqual(undefined, persistent_term:get(erldns_pipeline, undefined)).

sync(_) ->
    application:set_env(erldns, packet_pipeline, []),
    ?assertMatch({ok, _}, erldns_pipeline:start_link()),
    ?assertMatch({[], #{}}, persistent_term:get(erldns_pipeline, undefined)),
    application:set_env(erldns, packet_pipeline, [fun(A, _) -> A end]),
    ?assertEqual(ok, gen_server:call(erldns_pipeline, sync)),
    ?assertMatch({[_], #{}}, persistent_term:get(erldns_pipeline, undefined)).

survives_cast_and_calls(_) ->
    application:set_env(erldns, packet_pipeline, []),
    ?assertMatch({ok, _}, erldns_pipeline:start_link()),
    ?assertEqual(ok, gen_server:cast(erldns_pipeline, whatever)),
    ?assertEqual(not_implemented, gen_server:call(erldns_pipeline, whatever)),
    ?assert(is_pid(whereis(erldns_pipeline))).

configure_function_pipes(_) ->
    application:set_env(erldns, packet_pipeline, [fun(A, _) -> A end]),
    ?assertMatch({ok, _}, erldns_pipeline:start_link()),
    ?assertMatch({[_], #{}}, persistent_term:get(erldns_pipeline, undefined)).

fail_to_configure_bad_function_pipes(_) ->
    application:set_env(erldns, packet_pipeline, [fun(A, _, _) -> A end]),
    ?assertMatch(
        {error, {{badpipe, {function_pipe_has_wrong_arity, _}}, _}},
        erldns_pipeline:start_link()
    ).

configure_module_pipes_with_prepare_returns_disable(_) ->
    meck:new(?FUNCTION_NAME, [non_strict]),
    meck:expect(?FUNCTION_NAME, call, fun(Msg, _) -> Msg end),
    meck:expect(?FUNCTION_NAME, prepare, fun(_) -> disabled end),
    application:set_env(erldns, packet_pipeline, [?FUNCTION_NAME]),
    ?assertMatch({ok, _}, erldns_pipeline:start_link()),
    ?assertMatch({[], #{}}, persistent_term:get(erldns_pipeline, undefined)).

configure_module_pipes_with_prepare(_) ->
    meck:new(?FUNCTION_NAME, [non_strict]),
    meck:expect(?FUNCTION_NAME, call, fun(Msg, _) -> Msg end),
    meck:expect(?FUNCTION_NAME, prepare, fun(Opts) -> Opts end),
    application:set_env(erldns, packet_pipeline, [?FUNCTION_NAME]),
    ?assertMatch({ok, _}, erldns_pipeline:start_link()),
    ?assertMatch({[_], #{}}, persistent_term:get(erldns_pipeline, undefined)).

configure_module_pipes_with_bad_prepare(_) ->
    meck:new(?FUNCTION_NAME, [non_strict]),
    meck:expect(?FUNCTION_NAME, call, fun(Msg, _) -> Msg end),
    meck:expect(?FUNCTION_NAME, prepare, fun(_) -> not_a_map end),
    application:set_env(erldns, packet_pipeline, [?FUNCTION_NAME]),
    ?assertMatch(
        {error, {{badpipe, {module_init_returned_non_map, ?FUNCTION_NAME}}, _}},
        erldns_pipeline:start_link()
    ).

configure_module_pipes_without_prepare(_) ->
    meck:new(?FUNCTION_NAME, [non_strict]),
    meck:expect(?FUNCTION_NAME, call, fun(Msg, _) -> Msg end),
    application:set_env(erldns, packet_pipeline, [?FUNCTION_NAME]),
    ?assertMatch({ok, _}, erldns_pipeline:start_link()),
    ?assertMatch({[_], #{}}, persistent_term:get(erldns_pipeline, undefined)).

fail_to_configure_non_existing_module_pipe(_) ->
    application:set_env(erldns, packet_pipeline, [?FUNCTION_NAME]),
    ?assertMatch({error, {{badpipe, {module, nofile}}, _}}, erldns_pipeline:start_link()).

configure_module_pipe_without_call(_) ->
    meck:new(?FUNCTION_NAME, [non_strict]),
    application:set_env(erldns, packet_pipeline, [?FUNCTION_NAME]),
    ?assertMatch(
        {error, {{badpipe, module_does_not_export_call}, _}},
        erldns_pipeline:start_link()
    ).

pipe_returns_stop(_) ->
    Qs = [#dns_query{name = <<"example.com">>, type = ?DNS_TYPE_A}],
    Msg = #dns_message{qc = 1, questions = Qs},
    Fun = fun(M, _) -> {stop, M#dns_message{tc = true}} end,
    application:set_env(erldns, packet_pipeline, [Fun]),
    ?assertMatch({ok, _}, erldns_pipeline:start_link()),
    ?assertMatch({[_], #{}}, persistent_term:get(erldns_pipeline, undefined)),
    ?assertMatch(#dns_message{tc = true}, erldns_pipeline:call(Msg, def_opts())).

pipe_returns_new_msg(_) ->
    Qs = [#dns_query{name = <<"example.com">>, type = ?DNS_TYPE_A}],
    Msg = #dns_message{qc = 1, questions = Qs},
    Fun = fun(M, _) -> M#dns_message{tc = true} end,
    application:set_env(erldns, packet_pipeline, [Fun]),
    ?assertMatch({ok, _}, erldns_pipeline:start_link()),
    ?assertMatch({[_], #{}}, persistent_term:get(erldns_pipeline, undefined)),
    ?assertMatch(#dns_message{tc = true}, erldns_pipeline:call(Msg, def_opts())).

pipe_returns_msg_and_opts(_) ->
    Qs = [#dns_query{name = <<"example.com">>, type = ?DNS_TYPE_A}],
    Msg = #dns_message{qc = 1, questions = Qs},
    Fun = fun(M, O) -> {M#dns_message{tc = true}, O#{a => b}} end,
    application:set_env(erldns, packet_pipeline, [Fun]),
    ?assertMatch({ok, _}, erldns_pipeline:start_link()),
    ?assertMatch({[_], #{}}, persistent_term:get(erldns_pipeline, undefined)),
    ?assertMatch(#dns_message{tc = true}, erldns_pipeline:call(Msg, def_opts())).

pipe_returns_unexpected_value(_) ->
    Qs = [#dns_query{name = <<"example.com">>, type = ?DNS_TYPE_A}],
    Msg = #dns_message{qc = 1, questions = Qs},
    Fun = fun(_, _) -> #{} end,
    application:set_env(erldns, packet_pipeline, [Fun]),
    ?assertMatch({ok, _}, erldns_pipeline:start_link()),
    ?assertMatch({[_], #{}}, persistent_term:get(erldns_pipeline, undefined)),
    ?assertMatch(#dns_message{tc = false}, erldns_pipeline:call(Msg, def_opts())).

pipe_raises(_) ->
    Qs = [#dns_query{name = <<"example.com">>, type = ?DNS_TYPE_A}],
    Msg = #dns_message{qc = 1, questions = Qs},
    Fun = fun(_, _) -> erlang:error(an_error) end,
    application:set_env(erldns, packet_pipeline, [Fun]),
    ?assertMatch({ok, _}, erldns_pipeline:start_link()),
    ?assertMatch({[_], #{}}, persistent_term:get(erldns_pipeline, undefined)),
    ?assertMatch(#dns_message{tc = false}, erldns_pipeline:call(Msg, def_opts())).

def_opts() ->
    erldns_pipeline:def_opts().
