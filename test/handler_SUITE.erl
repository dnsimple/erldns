-module(handler_SUITE).
-compile([export_all, nowarn_export_all]).

-behaviour(ct_suite).

-include_lib("stdlib/include/assert.hrl").
-include_lib("dns_erlang/include/dns.hrl").

-define(DEF_HANDLER_VER, 3).

-spec all() -> [ct_suite:ct_test_def()].
all() ->
    [
        terminate_removes_pt,
        survives_cast_and_calls,
        configure_handlers,
        configure_handlers_bad_types,
        at_least_version_2,
        misses_callback,
        call_handlers,
        call_handlers_any,
        call_filters,
        call_map_nsec_rr_types
    ].

-spec init_per_testcase(ct_suite:ct_testcase(), ct_suite:ct_config()) -> ct_suite:ct_config().
init_per_testcase(_, Config) ->
    erlang:process_flag(trap_exit, true),
    Config.

-spec end_per_testcase(ct_suite:ct_testcase(), ct_suite:ct_config()) -> term().
end_per_testcase(_, _) ->
    meck:unload(),
    application:unset_env(erldns, packet_handlers),
    erlang:process_flag(trap_exit, false).

%% Tests
terminate_removes_pt(_) ->
    application:set_env(erldns, packet_handlers, []),
    ?assertMatch({ok, _}, erldns_handler:start_link()),
    erlang:exit(whereis(erldns_handler), normal),
    receive
        {'EXIT', _, normal} ->
            ok
    after 1000 -> ct:fail("erldns_pipeline did not die")
    end,
    ?assertEqual(undefined, persistent_term:get(erldns_handler, undefined)).

survives_cast_and_calls(_) ->
    application:set_env(erldns, packet_handlers, []),
    ?assertMatch({ok, _}, erldns_handler:start_link()),
    ?assertEqual(ok, gen_server:cast(erldns_handler, whatever)),
    ?assertEqual(not_implemented, gen_server:call(erldns_handler, whatever)),
    ?assert(is_pid(whereis(erldns_handler))).

configure_handlers(_) ->
    meck:new(?FUNCTION_NAME, [non_strict]),
    meck:expect(?FUNCTION_NAME, handle, fun(_, _, _, _) -> [] end),
    meck:expect(?FUNCTION_NAME, filter, fun(RRs) -> RRs end),
    meck:expect(?FUNCTION_NAME, nsec_rr_type_mapper, fun(T, _) -> T end),
    application:set_env(erldns, packet_handlers, [
        {?FUNCTION_NAME, [?DNS_TYPE_A, ~"AAAA"], ?DEF_HANDLER_VER}
    ]),
    ?assertMatch({ok, _}, erldns_handler:start_link()),
    ?assertMatch([_], persistent_term:get(erldns_handler, undefined)).

configure_handlers_bad_types(_) ->
    meck:new(?FUNCTION_NAME, [non_strict]),
    meck:expect(?FUNCTION_NAME, handle, fun(_, _, _, _) -> [] end),
    meck:expect(?FUNCTION_NAME, filter, fun(RRs) -> RRs end),
    meck:expect(?FUNCTION_NAME, nsec_rr_type_mapper, fun(T, _) -> T end),
    application:set_env(erldns, packet_handlers, [{?FUNCTION_NAME, [~"badtype"], ?DEF_HANDLER_VER}]),
    ?assertMatch(
        {error, {{badhandler, ?FUNCTION_NAME, {record_type, ~"badtype"}}, _}},
        erldns_handler:start_link()
    ).

at_least_version_2(_) ->
    meck:new(?FUNCTION_NAME, [non_strict]),
    meck:expect(?FUNCTION_NAME, handle, fun(_, _, _, _) -> [] end),
    meck:expect(?FUNCTION_NAME, filter, fun(RRs) -> RRs end),
    meck:expect(?FUNCTION_NAME, nsec_rr_type_mapper, fun(T, _) -> T end),
    application:set_env(erldns, packet_handlers, [{?FUNCTION_NAME, [], 1}]),
    ?assertMatch(
        {error, {{badhandler, ?FUNCTION_NAME, {version, 1}}, _}},
        erldns_handler:start_link()
    ).

misses_callback(_) ->
    meck:new(?FUNCTION_NAME, [non_strict]),
    meck:expect(?FUNCTION_NAME, handle, fun(_, _, _, _) -> [] end),
    meck:expect(?FUNCTION_NAME, nsec_rr_type_mapper, fun(T, _) -> T end),
    application:set_env(erldns, packet_handlers, [{?FUNCTION_NAME, [], ?DEF_HANDLER_VER}]),
    ?assertMatch(
        {error, {{badhandler, ?FUNCTION_NAME, module_does_not_export_call}, _}},
        erldns_handler:start_link()
    ).

call_handlers(_) ->
    meck_handler(?FUNCTION_NAME),
    Records = [#dns_rr{}, #dns_rr{}],
    Labels = [~"example", ~"com"],
    ?assertMatch(
        Records, erldns_handler:call_handlers(#dns_message{}, Labels, ?DNS_TYPE_A, Records)
    ).

call_handlers_any(_) ->
    meck_handler(?FUNCTION_NAME),
    Records = [#dns_rr{}, #dns_rr{}],
    Labels = [~"example", ~"com"],
    ?assertMatch(
        Records, erldns_handler:call_handlers(#dns_message{}, Labels, ?DNS_TYPE_ANY, Records)
    ).

call_filters(_) ->
    meck_handler(?FUNCTION_NAME),
    Records = [#dns_rr{}, #dns_rr{}],
    ?assertMatch([], erldns_handler:call_filters(Records)).

call_map_nsec_rr_types(_) ->
    meck_handler(?FUNCTION_NAME),
    Types = lists:sort([?DNS_TYPE_RRSIG, ?DNS_TYPE_NSEC, ?DNS_TYPE_NXNAME]),
    ?assertMatch(Types, erldns_handler:call_map_nsec_rr_types(?DNS_TYPE_A, Types)).

meck_handler(Name) ->
    meck:new(Name, [non_strict]),
    meck:expect(Name, handle, fun(_, _, _, RRs) -> RRs end),
    meck:expect(Name, filter, fun(_) -> [] end),
    meck:expect(Name, nsec_rr_type_mapper, fun(T, _) -> [T] end),
    application:set_env(erldns, packet_handlers, [
        {Name, [?DNS_TYPE_A, ?DNS_TYPE_AAAA], ?DEF_HANDLER_VER}
    ]),
    ?assertMatch({ok, _}, erldns_handler:start_link()).

def_opts() ->
    erldns_pipeline:def_opts().
