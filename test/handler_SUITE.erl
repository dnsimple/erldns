-module(handler_SUITE).
-compile([export_all, nowarn_export_all]).

-behaviour(ct_suite).

-include_lib("stdlib/include/assert.hrl").
-include_lib("dns_erlang/include/dns.hrl").

-define(DEFAULT_HANDLER_VERSION, 3).

-spec all() -> [ct_suite:ct_test_def()].
all() ->
    [
        {group, general},
        {group, nsec_type_mappers}
    ].

-spec groups() -> [ct_suite:ct_group_def()].
groups() ->
    [
        {general, [], [
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
        ]},
        {nsec_type_mappers, [], [
            %% Registration API requires gen_server - tested via integration.
            %% These tests verify the mapping logic using persistent_term directly.
            call_map_nsec_rr_types_with_standalone_mapper,
            call_map_nsec_rr_types_arity2_with_standalone_mapper,
            call_map_nsec_rr_types_no_mappers
        ]}
    ].

-spec init_per_group(ct_suite:ct_groupname(), ct_suite:ct_config()) -> ct_suite:ct_config().
init_per_group(nsec_type_mappers, Config) ->
    persistent_term:erase(erldns_handler),
    Config;
init_per_group(_, Config) ->
    Config.

-spec end_per_group(ct_suite:ct_group_name(), ct_suite:ct_config()) -> term().
end_per_group(nsec_type_mappers, _Config) ->
    persistent_term:erase(erldns_handler);
end_per_group(_, _Config) ->
    ok.

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
        {?FUNCTION_NAME, [?DNS_TYPE_A, ~"AAAA"], ?DEFAULT_HANDLER_VERSION}
    ]),
    ?assertMatch({ok, _}, erldns_handler:start_link()),
    ?assertMatch({[_], _}, persistent_term:get(erldns_handler, {[], []})).

configure_handlers_bad_types(_) ->
    meck:new(?FUNCTION_NAME, [non_strict]),
    meck:expect(?FUNCTION_NAME, handle, fun(_, _, _, _) -> [] end),
    meck:expect(?FUNCTION_NAME, filter, fun(RRs) -> RRs end),
    meck:expect(?FUNCTION_NAME, nsec_rr_type_mapper, fun(T, _) -> T end),
    application:set_env(erldns, packet_handlers, [
        {?FUNCTION_NAME, [~"badtype"], ?DEFAULT_HANDLER_VERSION}
    ]),
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
    application:set_env(erldns, packet_handlers, [{?FUNCTION_NAME, [], ?DEFAULT_HANDLER_VERSION}]),
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
        {Name, [?DNS_TYPE_A, ?DNS_TYPE_AAAA], ?DEFAULT_HANDLER_VERSION}
    ]),
    ?assertMatch({ok, _}, erldns_handler:start_link()).

def_opts() ->
    erldns_pipeline:def_opts().

%% ===================================================================
%% NSEC Type Mapper Tests
%% ===================================================================
%% These test the mapping logic. Registration API is tested via integration.

%% Verify call_map_nsec_rr_types/1 applies mappers to transform type list.
%% Maps custom types (e.g., 30003 ALIAS) to standard types (A=1, AAAA=28).
call_map_nsec_rr_types_with_standalone_mapper(_) ->
    MapperFun = fun
        (30003, _QType) -> [1, 28];
        (Type, _QType) -> [Type]
    end,
    %% Set up mappers via persistent_term (bypasses gen_server registration)
    Mappers = [{[30003], MapperFun}],
    persistent_term:put(erldns_handler, {[], Mappers}),
    Types = [2, 6, 30003, 46],
    Result = erldns_handler:call_map_nsec_rr_types(Types),
    %% Should map 30003 -> [1, 28] and sort uniquely
    ?assertEqual([1, 2, 6, 28, 46], Result).

%% Verify call_map_nsec_rr_types/2 uses QType to select mapping strategy.
%% ALIAS maps to AAAA for A queries, A for AAAA queries (complementary types).
call_map_nsec_rr_types_arity2_with_standalone_mapper(_) ->
    MapperFun = fun
        % For A query, return AAAA
        (30003, 1) -> [28];
        % For AAAA query, return A
        (30003, 28) -> [1];
        % For other queries, return both
        (30003, _) -> [1, 28];
        (Type, _) -> [Type]
    end,
    Mappers = [{[30003], MapperFun}],
    persistent_term:put(erldns_handler, {[], Mappers}),
    %% QType = A (1) -> ALIAS maps to AAAA
    Result1 = erldns_handler:call_map_nsec_rr_types(1, [2, 30003, 46]),
    ?assertEqual([2, 28, 46], Result1),
    %% QType = AAAA (28) -> ALIAS maps to A
    Result2 = erldns_handler:call_map_nsec_rr_types(28, [2, 30003, 46]),
    ?assertEqual([1, 2, 46], Result2).

%% Verify call_map_nsec_rr_types passes types through unchanged when no mappers.
call_map_nsec_rr_types_no_mappers(_) ->
    %% Empty handlers and mappers
    persistent_term:put(erldns_handler, {[], []}),
    Types = [1, 2, 5, 28],
    Result = erldns_handler:call_map_nsec_rr_types(Types),
    ?assertEqual(Types, Result),
    Result2 = erldns_handler:call_map_nsec_rr_types(1, Types),
    ?assertEqual(Types, Result2).
