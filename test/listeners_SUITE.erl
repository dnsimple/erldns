-module(listeners_SUITE).
-compile([export_all, nowarn_export_all]).

-behaviour(ct_suite).

-include_lib("stdlib/include/assert.hrl").
-include_lib("dns_erlang/include/dns.hrl").

-define(INGRESS_TIMEOUT, 50).
-define(UDP_LISTENER_NAME, udp_listener).
-define(TCP_LISTENER_NAME, tcp_listener).

-spec all() -> [ct_suite:ct_test_def()].
all() ->
    [
        {group, configuration},
        {group, udp},
        {group, tcp},
        sched_mon_coverage,
        reset_queues,
        stats
    ].

-spec groups() -> [ct_suite:ct_group_def()].
groups() ->
    [
        {configuration, [sequence], [
            name_must_be_atom,
            port_must_be_inet_port,
            transport_must_be_tcp_udp_or_both,
            p_factor_must_be_positive,
            ip_must_be_inet_parseable,
            codel
        ]},
        {udp, [], [
            udp_halted,
            udp_overrun,
            udp_drop_packets,
            udp_reactivate,
            udp_coverage,
            udp_encoder_failure,
            udp_load_shedding
        ]},
        {tcp, [sequence], [
            tcp_halted,
            tcp_closed,
            tcp_overrun,
            tcp_drop_packets,
            tcp_encoder_failure,
            tcp_load_shedding,
            tcp_in_pieces
        ]}
    ].

-spec init_per_suite(ct_suite:ct_config()) -> ct_suite:ct_config().
init_per_suite(Config) ->
    application:ensure_all_started([ranch, worker_pool, telemetry]),
    Config.

-spec end_per_suite(ct_suite:ct_config()) -> term().
end_per_suite(_) ->
    [application:stop(App) || App <- [ranch, worker_pool, telemetry]],
    application:unset_env(erldns, ingress_udp_request_timeout),
    application:unset_env(erldns, ingress_tcp_request_timeout),
    application:unset_env(erldns, packet_pipeline),
    application:unset_env(erldns, listeners).

-spec init_per_group(ct_suite:ct_groupname(), ct_suite:ct_config()) -> ct_suite:ct_config().
init_per_group(udp, Config) ->
    AppConfig = [
        {erldns, [
            {listeners, [#{name => ?UDP_LISTENER_NAME, transport => udp, port => 8053}]},
            {ingress_udp_request_timeout, ?INGRESS_TIMEOUT}
        ]}
    ],
    application:set_env(AppConfig),
    Config;
init_per_group(tcp, Config) ->
    AppConfig = [
        {erldns, [
            {listeners, [#{name => ?TCP_LISTENER_NAME, transport => tcp, port => 8053}]},
            {ingress_tcp_request_timeout, ?INGRESS_TIMEOUT}
        ]}
    ],
    application:set_env(AppConfig),
    Config;
init_per_group(_, Config) ->
    Config.

-spec end_per_group(ct_suite:ct_groupname(), ct_suite:ct_config()) -> term().
end_per_group(udp, _Config) ->
    ok;
end_per_group(tcp, _Config) ->
    ok;
end_per_group(_, _Config) ->
    ok.

-spec init_per_testcase(ct_suite:ct_testcase(), ct_suite:ct_config()) -> ct_suite:ct_config().
init_per_testcase(_, Config) ->
    erlang:process_flag(trap_exit, true),
    Config.

-spec end_per_testcase(ct_suite:ct_testcase(), ct_suite:ct_config()) -> term().
end_per_testcase(TC, Config) ->
    telemetry:detach(TC),
    Config.

%% Tests
name_must_be_atom(_) ->
    application:set_env(erldns, listeners, [#{}]),
    ?assertMatch({error, {{invalid_listener, name, #{}}, _}}, erldns_listeners:start_link()),
    application:set_env(erldns, listeners, [#{name => ~"bad"}]),
    ?assertMatch(
        {error, {{invalid_listener, name, #{name := <<"bad">>}}, _}}, erldns_listeners:start_link()
    ),
    application:set_env(erldns, listeners, [#{name => good_name, port => 0}]),
    ?assertMatch({ok, _}, erldns_listeners:start_link()).

port_must_be_inet_port(_) ->
    application:set_env(erldns, listeners, [#{name => ?FUNCTION_NAME, port => bad_port}]),
    ?assertMatch(
        {error, {{invalid_listener, port, #{port := bad_port}}, _}},
        erldns_listeners:start_link()
    ),
    application:set_env(erldns, listeners, [#{name => ?FUNCTION_NAME, port => 8798798}]),
    ?assertMatch(
        {error, {{invalid_listener, port, #{port := 8798798}}, _}},
        erldns_listeners:start_link()
    ),
    application:set_env(erldns, listeners, [#{name => ?FUNCTION_NAME, port => 0}]),
    ?assertMatch({ok, _}, erldns_listeners:start_link()).

transport_must_be_tcp_udp_or_both(_) ->
    application:set_env(erldns, listeners, [#{name => ?FUNCTION_NAME, transport => ~"bad"}]),
    ?assertMatch(
        {error, {{invalid_listener, transport, #{transport := <<"bad">>}}, _}},
        erldns_listeners:start_link()
    ),
    application:set_env(erldns, listeners, [#{name => ?FUNCTION_NAME, transport => other}]),
    ?assertMatch(
        {error, {{invalid_listener, transport, #{transport := other}}, _}},
        erldns_listeners:start_link()
    ),
    application:set_env(erldns, listeners, [#{name => ?FUNCTION_NAME, transport => udp, port => 0}]),
    ?assertMatch({ok, _}, erldns_listeners:start_link()),
    gen_server:stop(erldns_listeners),
    application:set_env(erldns, listeners, [#{name => ?FUNCTION_NAME, transport => tcp, port => 0}]),
    ?assertMatch({ok, _}, erldns_listeners:start_link()),
    gen_server:stop(erldns_listeners),
    application:set_env(erldns, listeners, [#{name => ?FUNCTION_NAME, transport => both, port => 0}]),
    ?assertMatch({ok, _}, erldns_listeners:start_link()).

codel(_) ->
    %% Test 1: Initialization variants
    C1 = erldns_codel:new(),
    ?assert(is_tuple(C1)),
    C2 = erldns_codel:new(200),
    ?assert(is_tuple(C2)),
    C3 = erldns_codel:new(200, 10),
    ?assert(is_tuple(C3)),
    %% Test 2: Empty queue - should always continue and reset first_above_time
    Now = erlang:monotonic_time(),
    {continue, C4} = erldns_codel:dequeue(C1, Now, Now - 1000, 0),
    %% Verify empty queue resets first_above_time by checking behavior
    %% If first_above_time was reset, next call with high sojourn time should set it again
    {continue, C4a} = erldns_codel:dequeue(C4, Now, Now - 1000000, 10),
    %% Should have set first_above_time (not continue immediately to drop)
    {continue, C4b} = erldns_codel:dequeue(C4a, Now + 1, Now - 1000000, 10),
    ?assertMatch({continue, _}, erldns_codel:dequeue(C4b, Now + 2, Now - 1000000, 10)),
    %% Test 3: Normal operation - sojourn time below target
    %% Target is 5ms (in native time units after conversion)
    TargetMs = 5,
    TargetNative = erlang:convert_time_unit(TargetMs, millisecond, native),
    %% Half of target
    IngressTs = Now - (TargetNative div 2),
    {continue, C5} = erldns_codel:dequeue(C1, Now, IngressTs, 10),
    %% Verify not dropping by checking it doesn't drop on next call
    {continue, C5a} = erldns_codel:dequeue(C5, Now + 1, IngressTs, 10),
    ?assertMatch({continue, _}, erldns_codel:dequeue(C5a, Now + 2, IngressTs, 10)),
    %% Test 4: Sojourn time below target but queue > MAX_PACKET
    %% Should continue and reset first_above_time
    {continue, C6} = erldns_codel:dequeue(C1, Now, IngressTs, 2),
    %% Verify first_above_time was reset by checking it sets again on high sojourn
    {continue, C6a} = erldns_codel:dequeue(C6, Now, Now - 1000000, 10),
    ?assertMatch({continue, _}, erldns_codel:dequeue(C6a, Now + 1, Now - 1000000, 10)),
    %% Test 5: Entering drop state - sojourn time above target for interval
    IntervalMs = 100,
    IntervalNative = erlang:convert_time_unit(IntervalMs, millisecond, native),
    %% Create a packet that's been in queue for target + interval
    OldIngressTs = Now - TargetNative - IntervalNative - 1000,
    %% First call: should set first_above_time
    {continue, C7} = erldns_codel:dequeue(C1, Now, OldIngressTs, 10),
    %% Verify first_above_time was set by waiting and checking drop occurs
    %% Estimate first_above_time: Now + IntervalNative
    FutureNow = Now + IntervalNative + 1000,
    Result8 = erldns_codel:dequeue(C7, FutureNow, OldIngressTs, 10),
    {drop, C8} = Result8,
    ?assertMatch({drop, _}, Result8),
    %% Test 6: Dropping state - drop when drop_next_time <= Now
    %% First drop should happen immediately (drop_next_time was just set to FutureNow + IntervalNative)
    %% So we need to wait until drop_next_time
    DropNextTime = FutureNow + IntervalNative,
    Result9 = erldns_codel:dequeue(C8, DropNextTime, OldIngressTs, 10),
    {drop, C9} = Result9,
    ?assertMatch({drop, _}, Result9),
    %% Test 7: Dropping state - continue when drop_next_time > Now
    %% drop_next_time is in the future, so we should continue
    Result10 = erldns_codel:dequeue(C9, DropNextTime + 1, OldIngressTs, 10),
    {continue, C10} = Result10,
    ?assertMatch({continue, _}, Result10),
    %% Test 8: Leaving drop state - sojourn time goes below target
    GoodIngressTs = FutureNow + 1000 - (TargetNative div 2),
    {continue, C11} = erldns_codel:dequeue(C10, FutureNow + 1000, GoodIngressTs, 10),
    %% Verify left drop state by checking it doesn't drop immediately on next high sojourn
    Result11a = erldns_codel:dequeue(C11, FutureNow + 2000, OldIngressTs, 10),
    ?assertMatch({continue, _}, Result11a),
    %% Test 9: Hysteresis - re-entering drop state soon after leaving
    %% To test hysteresis, we need to simulate having dropped before
    %% Start fresh and enter drop state twice to build up count
    C12 = erldns_codel:new(),
    BadIngressTs2 = Now - TargetNative - IntervalNative - 1000,
    {continue, C12a} = erldns_codel:dequeue(C12, Now, BadIngressTs2, 10),
    EnterNow1 = Now + IntervalNative + 1000,
    {drop, C12b} = erldns_codel:dequeue(C12a, EnterNow1, BadIngressTs2, 10),
    %% Drop a few packets to build up count
    DropTime1 = EnterNow1 + IntervalNative,
    {drop, C12c} = erldns_codel:dequeue(C12b, DropTime1, BadIngressTs2, 10),
    DropTime2 = DropTime1 + round(IntervalNative / math:sqrt(2)),
    {drop, C12d} = erldns_codel:dequeue(C12c, DropTime2, BadIngressTs2, 10),
    DropTime3 = DropTime2 + round(IntervalNative / math:sqrt(3)),
    {drop, C12e} = erldns_codel:dequeue(C12d, DropTime3, BadIngressTs2, 10),
    %% Now leave drop state
    GoodIngressTs2 = DropTime3 + 1000 - (TargetNative div 2),
    {continue, C12f} = erldns_codel:dequeue(C12e, DropTime3 + 1000, GoodIngressTs2, 10),
    %% Re-enter drop state within hysteresis window (16 * interval)
    HysteresisWindow = 16 * IntervalNative,
    NearFutureNow = DropTime3 + 1000 + (HysteresisWindow div 2),
    BadIngressTs3 = NearFutureNow - TargetNative - IntervalNative - 1000,
    Result13 = erldns_codel:dequeue(C12f, NearFutureNow, BadIngressTs3, 10),
    {continue, C13} = Result13,
    ?assertMatch({continue, _}, Result13),
    %% Wait for interval to pass and enter drop state
    HysteresisFutureNow = NearFutureNow + IntervalNative + 1000,
    Result14 = erldns_codel:dequeue(C13, HysteresisFutureNow, BadIngressTs3, 10),
    ?assertMatch({drop, _}, Result14),
    %% Test 10: Control law - count = 1
    %% Need to enter drop state first, which sets count = 1
    C15 = erldns_codel:new(),
    {continue, C15a} = erldns_codel:dequeue(C15, Now, OldIngressTs, 10),
    EnterDropNow2 = Now + IntervalNative + 1000,
    Result16 = erldns_codel:dequeue(C15a, EnterDropNow2, OldIngressTs, 10),
    {drop, C16} = Result16,
    ?assertMatch({drop, _}, Result16),
    %% drop_next_time should be Now + Interval for count = 1
    %% Verify by checking next drop happens at that time
    ExpectedDropNext1 = EnterDropNow2 + IntervalNative,
    Result16a = erldns_codel:dequeue(C16, ExpectedDropNext1, OldIngressTs, 10),
    {drop, C16a} = Result16a,
    ?assertMatch({drop, _}, Result16a),
    %% Test 11: Control law - count > 1
    %% Continue dropping to build up count
    DropTime4 = ExpectedDropNext1 + round(IntervalNative / math:sqrt(2)),
    Result17 = erldns_codel:dequeue(C16a, DropTime4, OldIngressTs, 10),
    {drop, C17} = Result17,
    ?assertMatch({drop, _}, Result17),
    DropTime5 = DropTime4 + round(IntervalNative / math:sqrt(3)),
    Result18 = erldns_codel:dequeue(C17, DropTime5, OldIngressTs, 10),
    ?assertMatch({drop, _}, Result18),
    %% Test 12: Edge case - sojourn time exactly at target
    ExactTargetIngressTs = Now - TargetNative,
    {continue, C19} = erldns_codel:dequeue(C1, Now, ExactTargetIngressTs, 10),
    %% Should not drop (sojourn time is at target, not above)
    Result19a = erldns_codel:dequeue(C19, Now + 1, ExactTargetIngressTs, 10),
    ?assertMatch({continue, _}, Result19a),
    %% Test 13: Edge case - sojourn time just above target but not for full interval
    JustAboveIngressTs = Now - TargetNative - 100,
    {continue, C20} = erldns_codel:dequeue(C1, Now, JustAboveIngressTs, 10),
    %% Should not drop yet (need to wait for interval)
    Result20a = erldns_codel:dequeue(C20, Now + 1, JustAboveIngressTs, 10),
    ?assertMatch({continue, _}, Result20a),
    %% Test 14: Edge case - queue length exactly at MAX_PACKET (1)
    Result21 = erldns_codel:dequeue(C1, Now, IngressTs, 1),
    ?assertMatch({continue, _}, Result21),
    %% Test 15: Multiple drops in sequence
    %% Create a state that's dropping with drop_next_time = Now
    C22 = erldns_codel:new(),
    {continue, C22a} = erldns_codel:dequeue(C22, Now, OldIngressTs, 10),
    EnterDropNow3 = Now + IntervalNative + 1000,
    {drop, C22b} = erldns_codel:dequeue(C22a, EnterDropNow3, OldIngressTs, 10),
    %% Now drop_next_time should be EnterDropNow3 + IntervalNative
    DropTime6 = EnterDropNow3 + IntervalNative,
    Result23 = erldns_codel:dequeue(C22b, DropTime6, OldIngressTs, 10),
    ?assertMatch({drop, _}, Result23),
    %% Test 16: Verify state transitions
    %% Start normal -> enter drop -> drop packets -> leave drop
    C24 = erldns_codel:new(),
    StartNow = erlang:monotonic_time(),
    VeryOldIngressTs = StartNow - (2 * IntervalNative) - TargetNative,
    %% First: normal operation
    Result25 = erldns_codel:dequeue(C24, StartNow, VeryOldIngressTs, 10),
    {continue, C25} = Result25,
    ?assertMatch({continue, _}, Result25),
    %% Second: enter drop state
    EnterDropNow4 = StartNow + IntervalNative + 1000,
    Result26 = erldns_codel:dequeue(C25, EnterDropNow4, VeryOldIngressTs, 10),
    {drop, C26} = Result26,
    ?assertMatch({drop, _}, Result26),
    %% Third: drop a packet
    DropTime7 = EnterDropNow4 + IntervalNative,
    Result27 = erldns_codel:dequeue(C26, DropTime7, VeryOldIngressTs, 10),
    {drop, C27} = Result27,
    ?assertMatch({drop, _}, Result27),
    %% Fourth: sojourn time goes below target, leave drop state
    GoodIngressTs3 = DropTime7 + 1000 - (TargetNative div 2),
    Result28 = erldns_codel:dequeue(C27, DropTime7 + 1000, GoodIngressTs3, 10),
    ?assertMatch({continue, _}, Result28).

p_factor_must_be_positive(_) ->
    application:set_env(erldns, listeners, [#{name => ?FUNCTION_NAME, parallel_factor => bad}]),
    ?assertMatch(
        {error, {{invalid_listener, parallel_factor, #{parallel_factor := bad}}, _}},
        erldns_listeners:start_link()
    ),
    application:set_env(erldns, listeners, [#{name => ?FUNCTION_NAME, parallel_factor => 0}]),
    ?assertMatch(
        {error, {{invalid_listener, parallel_factor, #{parallel_factor := 0}}, _}},
        erldns_listeners:start_link()
    ),
    application:set_env(erldns, listeners, [
        #{name => ?FUNCTION_NAME, parallel_factor => 1, port => 0}
    ]),
    ?assertMatch({ok, _}, erldns_listeners:start_link()).

ip_must_be_inet_parseable(_) ->
    application:set_env(erldns, listeners, [#{name => ?FUNCTION_NAME, ip => bad}]),
    ?assertMatch(
        {error, {{invalid_listener, ip, #{ip := bad}}, _}},
        erldns_listeners:start_link()
    ),
    application:set_env(erldns, listeners, [#{name => ?FUNCTION_NAME, ip => 0}]),
    ?assertMatch(
        {error, {{invalid_listener, ip, #{ip := 0}}, _}},
        erldns_listeners:start_link()
    ),
    application:set_env(erldns, listeners, [#{name => ?FUNCTION_NAME, ip => "none"}]),
    ?assertMatch(
        {error, {{invalid_listener, ip, #{ip := "none"}}, _}},
        erldns_listeners:start_link()
    ),
    application:set_env(erldns, listeners, [#{name => ?FUNCTION_NAME, ip => any, port => 0}]),
    ?assertMatch({ok, _}, erldns_listeners:start_link()),
    gen_server:stop(erldns_listeners),
    application:set_env(erldns, listeners, [
        #{name => ?FUNCTION_NAME, ip => {0, 0, 0, 0}, port => 0}
    ]),
    ?assertMatch({ok, _}, erldns_listeners:start_link()),
    gen_server:stop(erldns_listeners),
    application:set_env(erldns, listeners, [
        #{name => ?FUNCTION_NAME, ip => {0, 0, 0, 0, 0, 0, 0, 0}, port => 0}
    ]),
    ?assertMatch({ok, _}, erldns_listeners:start_link()),
    gen_server:stop(erldns_listeners),
    application:set_env(erldns, listeners, [#{name => ?FUNCTION_NAME, ip => "::0", port => 0}]),
    ?assertMatch({ok, _}, erldns_listeners:start_link()),
    gen_server:stop(erldns_listeners),
    application:set_env(erldns, listeners, [#{name => ?FUNCTION_NAME, ip => "0.0.0.0", port => 0}]),
    ?assertMatch({ok, _}, erldns_listeners:start_link()).

udp_halted(_) ->
    prepare_test(?FUNCTION_NAME, timeout, [fun halting_pipe/2]),
    Packet = packet(),
    {ok, Socket} = gen_udp:open(0, [binary, {active, false}]),
    ok = gen_udp:send(Socket, {127, 0, 0, 1}, 8053, Packet),
    {error, timeout} = gen_udp:recv(Socket, 65535, 500),
    assert_no_telemetry_event().

udp_overrun(_) ->
    prepare_test(?FUNCTION_NAME, timeout, [fun sleeping_pipe/2]),
    Packet = packet(),
    {ok, Socket} = gen_udp:open(0, [binary, {active, false}]),
    ok = gen_udp:send(Socket, {127, 0, 0, 1}, 8053, Packet),
    assert_telemetry_event(timeout),
    ok.

udp_drop_packets(_) ->
    prepare_test(?FUNCTION_NAME, dropped, [fun pause_pipe/2]),
    Iterations = 500,
    Packet = packet(),
    {ok, Socket} = gen_udp:open(0, [binary, {active, false}]),
    [ok = gen_udp:send(Socket, {127, 0, 0, 1}, 8053, Packet) || _ <- lists:seq(1, Iterations)],
    assert_telemetry_event(dropped).

udp_reactivate(_) ->
    prepare_test(?FUNCTION_NAME, dropped, []),
    Iterations = 5000,
    Packet = packet(),
    {ok, Socket} = gen_udp:open(0, [binary, {active, false}]),
    [request_response(udp, Socket, Packet) || _ <- lists:seq(1, Iterations)].

udp_coverage(_) ->
    prepare_test(?FUNCTION_NAME, timeout, []),
    Children = supervisor:which_children(erldns_listeners),
    {_, Me, _, _} = lists:keyfind(?UDP_LISTENER_NAME, 1, Children),
    [{_, AccSup, _, _}, {WorkersPool, _, _, _}] = supervisor:which_children(Me),
    [{_, AcceptorPid, _, _} | _] = supervisor:which_children(AccSup),
    gen_server:call(AcceptorPid, anything),
    gen_server:cast(AcceptorPid, anything),
    erlang:send(AcceptorPid, anything),
    wpool:call(WorkersPool, anything, random_worker),
    wpool:cast(WorkersPool, anything, random_worker),
    wpool_pool:random_worker(WorkersPool) ! anything.

udp_encoder_failure(_) ->
    prepare_test(?FUNCTION_NAME, timeout, [fun bad_record/2]),
    Packet = packet(),
    {ok, Socket} = gen_udp:open(0, [binary, {active, false}]),
    Response = request_response(udp, Socket, Packet),
    ?assertEqual(?DNS_RCODE_SERVFAIL, Response#dns_message.rc, Response).

udp_load_shedding(_) ->
    [spawn_link(fun waste_fun/0) || _ <- lists:seq(1, erlang:system_info(schedulers))],
    prepare_test(?FUNCTION_NAME, delayed, [fun sleeping_pipe/2]),
    [spawn_link(fun bombard_udp_fun/0) || _ <- lists:seq(1, erlang:system_info(schedulers))],
    assert_telemetry_event(delayed).

tcp_in_pieces(_) ->
    application:set_env(erldns, ingress_tcp_request_timeout, 1000),
    prepare_test(?FUNCTION_NAME, timeout, []),
    Packet = packet(),
    P1 = binary:part(Packet, 0, 10),
    P2 = binary:part(Packet, 10, byte_size(Packet) - 10),
    ?assertMatch(Packet, iolist_to_binary([P1, P2]), Packet),
    {ok, Socket1} = gen_tcp:connect(
        {127, 0, 0, 1}, 8053, [binary, {packet, raw}, {active, false}], 1000
    ),
    ok = gen_tcp:send(Socket1, [<<(byte_size(Packet)):16>>, P1]),
    ct:sleep(50),
    ok = gen_tcp:send(Socket1, P2),
    {ok, <<_:16, RecvPacket/binary>>} = gen_tcp:recv(Socket1, 0, 2000),
    Response = dns:decode_message(RecvPacket),
    ?assertMatch(#dns_message{}, Response).

tcp_closed(_) ->
    prepare_test(?FUNCTION_NAME, timeout, [fun sleeping_pipe/2]),
    {ok, Socket1} = gen_tcp:connect(
        {127, 0, 0, 1}, 8053, [binary, {packet, raw}, {active, false}], 1000
    ),
    ok = gen_tcp:send(Socket1, [<<1024:16>>, ~"random_data"]),
    ok = gen_tcp:close(Socket1),
    {ok, Socket2} = gen_tcp:connect(
        {127, 0, 0, 1}, 8053, [binary, {packet, 2}, {active, false}], 1000
    ),
    ok = gen_tcp:close(Socket2),
    assert_no_telemetry_event().

tcp_halted(_) ->
    prepare_test(?FUNCTION_NAME, timeout, [fun halting_pipe/2]),
    Packet = packet(),
    {ok, Socket1} = gen_tcp:connect(
        {127, 0, 0, 1}, 8053, [binary, {packet, raw}, {active, false}], 1000
    ),
    ok = gen_tcp:send(Socket1, [<<(byte_size(Packet)):16>>, Packet]),
    {error, closed} = gen_tcp:recv(Socket1, 0, 2000),
    assert_no_telemetry_event().

tcp_overrun(_) ->
    prepare_test(?FUNCTION_NAME, timeout, [fun sleeping_pipe/2]),
    Packet = packet(),
    {ok, Socket1} = gen_tcp:connect(
        {127, 0, 0, 1}, 8053, [binary, {packet, 2}, {active, false}], 1000
    ),
    ok = gen_tcp:send(Socket1, Packet),
    assert_telemetry_event(timeout).

tcp_drop_packets(_) ->
    prepare_test(?FUNCTION_NAME, timeout, [fun sleeping_pipe/2]),
    _ = [
        spawn_link(fun bombard_tcp_fun/0)
     || _ <- lists:seq(1, erlang:system_info(schedulers))
    ],
    assert_telemetry_event(timeout).

tcp_load_shedding(_) ->
    _ = [spawn_link(fun waste_fun/0) || _ <- lists:seq(1, erlang:system_info(schedulers))],
    prepare_test(?FUNCTION_NAME, delayed, [fun sleeping_pipe/2]),
    _ = [
        spawn_link(fun bombard_tcp_fun/0)
     || _ <- lists:seq(1, erlang:system_info(schedulers))
    ],
    assert_telemetry_event(delayed).

sched_mon_coverage(_) ->
    AppConfig = [
        {erldns, [
            {listeners, []},
            {packet_pipeline, []},
            {ingress_udp_request_timeout, ?INGRESS_TIMEOUT}
        ]}
    ],
    application:set_env(AppConfig),
    ?assertMatch({ok, _}, erldns_listeners:start_link()),
    Children = supervisor:which_children(erldns_listeners),
    {_, Mon, _, _} = lists:keyfind(erldns_sch_mon, 1, Children),
    Mon ! anything,
    gen_server:cast(Mon, anything),
    gen_server:call(Mon, anything),
    ?assert(erlang:is_process_alive(Mon)).

tcp_encoder_failure(_) ->
    Packet = packet(),
    application:set_env(erldns, ingress_udp_request_timeout, ?INGRESS_TIMEOUT),
    application:set_env(erldns, packet_pipeline, [fun bad_record/2]),
    ?assertMatch({ok, _}, erldns_pipeline_worker:start_link()),
    ?assertMatch({ok, _}, erldns_listeners:start_link()),
    {ok, Socket} = gen_tcp:connect(
        {127, 0, 0, 1}, 8053, [binary, {packet, 2}, {active, false}], 1000
    ),
    Response = request_response(tcp, Socket, Packet),
    ct:pal("Value ~p~n", [Response]),
    ?assertEqual(?DNS_RCODE_SERVFAIL, Response#dns_message.rc).

stats(_) ->
    Listeners = [#{name => stats_1, port => 8053}, #{name => stats_2, port => 8054}],
    application:set_env(erldns, listeners, Listeners),
    ?assertMatch({ok, _}, erldns_listeners:start_link()),
    ?assertMatch(
        #{
            {stats_1, udp} := #{queue_length := _},
            {stats_2, udp} := #{queue_length := _},
            {stats_1, tcp} := #{queue_length := _},
            {stats_2, tcp} := #{queue_length := _}
        },
        erldns_listeners:get_stats()
    ).

reset_queues(_) ->
    AppConfig = [
        {erldns, [
            {listeners, [#{name => ?FUNCTION_NAME, port => 8053}]},
            {packet_pipeline, [fun sleeping_pipe/2]}
        ]}
    ],
    application:set_env(AppConfig),
    ?assertMatch({ok, _}, erldns_sup:start_link()),
    Udps = [spawn_link(fun bombard_udp_fun/0) || _ <- lists:seq(1, erlang:system_info(schedulers))],
    Tcps = [spawn_link(fun bombard_tcp_fun/0) || _ <- lists:seq(1, erlang:system_info(schedulers))],
    Pids = Udps ++ Tcps,
    ct:sleep(100),
    ?assertMatch(
        #{
            {?FUNCTION_NAME, udp} := #{queue_length := N},
            {?FUNCTION_NAME, tcp} := #{queue_length := M}
        } when 0 < N andalso 0 < M,
        erldns_listeners:get_stats()
    ),
    [exit(Pid, kill) || Pid <- Pids],
    ?assert(erldns_listeners:reset_queues()),
    ct:sleep(100),
    ?assertMatch(
        #{
            {?FUNCTION_NAME, udp} := #{queue_length := 0},
            {?FUNCTION_NAME, tcp} := #{queue_length := 0}
        },
        erldns_listeners:get_stats()
    ).

def_opts() ->
    erldns_pipeline:def_opts().

request_response(udp, Socket, Packet) ->
    ok = gen_udp:send(Socket, {127, 0, 0, 1}, 8053, Packet),
    {ok, {_, _, RecvPacket}} = gen_udp:recv(Socket, 65535, 2000),
    Response = dns:decode_message(RecvPacket),
    ?assertMatch(#dns_message{}, Response),
    Response;
request_response(tcp, Socket, Packet) ->
    ok = gen_tcp:send(Socket, Packet),
    {ok, RecvPacket} = gen_tcp:recv(Socket, 0, 2000),
    Response = dns:decode_message(RecvPacket),
    ?assertMatch(#dns_message{}, Response),
    Response.

telemetry_handler(EventName, Measurements, Metadata, Pid) ->
    ct:pal("EventName ~p~n", [EventName]),
    Pid ! {EventName, Measurements, Metadata}.

assert_telemetry_event(Type) ->
    receive
        {[erldns, request, Type], _, _} ->
            ok;
        M ->
            ct:pal("Unexpected message ~p~n", [M]),
            assert_telemetry_event(Type)
    after 5000 ->
        ct:fail("Telemetry event not triggered")
    end.

assert_no_telemetry_event() ->
    receive
        {[erldns, pipeline, Name], _, _} ->
            ct:fail("Telemetry event triggered: ~p", [Name])
    after 100 ->
        ok
    end.

pause_pipe(A, _) ->
    ct:sleep(35),
    A.

sleeping_pipe(A, _) ->
    ct:sleep(500),
    A.

halting_pipe(_, _) ->
    halt.

bad_record(A, _) ->
    A#dns_message{authority = [#dns_query{}]}.

bombard_udp_fun() ->
    Packet = packet(),
    {ok, Socket} = gen_udp:open(0, [binary, {active, false}]),
    F = fun F(S, P) ->
        ok = gen_udp:send(S, {127, 0, 0, 1}, 8053, P),
        F(S, P)
    end,
    F(Socket, Packet).

bombard_tcp_fun() ->
    Packet = packet(),
    F = fun F(P) ->
        {ok, Socket} = gen_tcp:connect(
            {127, 0, 0, 1}, 8053, [binary, {packet, 2}, {active, false}], 1000
        ),
        gen_tcp:send(Socket, P),
        F(P)
    end,
    F(Packet).

waste_fun() ->
    waste_fun().

attach_to_telemetry(Name, Type, Pid) ->
    ok = telemetry:attach(Name, [erldns, request, Type], fun ?MODULE:telemetry_handler/4, Pid).

packet() ->
    Q = #dns_query{name = ~"example.com", type = ?DNS_TYPE_A},
    Msg = #dns_message{qc = 1, questions = [Q]},
    dns:encode_message(Msg).

prepare_test(Name, TelemetryEvent, Pipeline) ->
    application:set_env(erldns, packet_pipeline, Pipeline),
    attach_to_telemetry(Name, TelemetryEvent, self()),
    ?assertMatch({ok, _}, erldns_pipeline_worker:start_link()),
    ?assertMatch({ok, _}, erldns_listeners:start_link()).
