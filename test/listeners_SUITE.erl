-module(listeners_SUITE).
-compile([export_all, nowarn_export_all]).

-behaviour(ct_suite).

-include_lib("stdlib/include/assert.hrl").
-include_lib("dns_erlang/include/dns.hrl").

-spec all() -> [ct_suite:ct_test_def()].
all() ->
    [
        name_must_be_atom,
        port_must_be_inet_port,
        transport_must_be_tcp_udp_or_both,
        p_factor_must_be_positive,
        ip_must_be_inet_parseable,
        tcp_overrun,
        udp_overrun,
        udp_drop_packets,
        tcp_drop_packets,
        udp_reactivate,
        udp_coverage,
        sched_mon_coverage,
        udp_encoder_failure,
        tcp_encoder_failure,
        stats,
        udp_load_shedding,
        tcp_load_shedding,
        reset_queues
    ].

-spec init_per_suite(ct_suite:ct_config()) -> ct_suite:ct_config().
init_per_suite(Config) ->
    application:ensure_all_started([ranch, worker_pool, telemetry]),
    Config.

-spec end_per_suite(ct_suite:ct_config()) -> term().
end_per_suite(_) ->
    [application:stop(App) || App <- [ranch, worker_pool, telemetry]].

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

tcp_overrun(_) ->
    attach_to_telemetry(?FUNCTION_NAME, timeout, self()),
    Packet = packet(),
    application:set_env(erldns, ingress_tcp_request_timeout, 50),
    application:set_env(erldns, listeners, [
        #{name => ?FUNCTION_NAME, transport => tcp, port => 8053}
    ]),
    application:set_env(erldns, packet_pipeline, [fun sleeping_pipe/2]),
    ?assertMatch({ok, _}, erldns_pipeline_worker:start_link()),
    ?assertMatch({ok, _}, erldns_listeners:start_link()),
    {ok, Socket1} = gen_tcp:connect(
        {127, 0, 0, 1}, 8053, [binary, {packet, 2}, {active, false}], 1000
    ),
    ok = gen_tcp:send(Socket1, Packet),
    assert_telemetry_event(timeout).

udp_overrun(_) ->
    attach_to_telemetry(?FUNCTION_NAME, timeout, self()),
    Packet = packet(),
    application:set_env(erldns, ingress_udp_request_timeout, 50),
    application:set_env(erldns, listeners, [
        #{name => ?FUNCTION_NAME, transport => udp, port => 8053}
    ]),
    application:set_env(erldns, packet_pipeline, [fun sleeping_pipe/2]),
    ?assertMatch({ok, _}, erldns_pipeline_worker:start_link()),
    ?assertMatch({ok, _}, erldns_listeners:start_link()),
    {ok, Socket} = gen_udp:open(0, [binary, {active, false}]),
    ok = gen_udp:send(Socket, {127, 0, 0, 1}, 8053, Packet),
    assert_telemetry_event(timeout),
    ok.

tcp_drop_packets(_) ->
    attach_to_telemetry(?FUNCTION_NAME, timeout, self()),
    AppConfig = [
        {erldns, [
            {listeners, [#{name => ?FUNCTION_NAME, transport => tcp, port => 8053}]},
            {packet_pipeline, [fun sleeping_pipe/2]},
            {ingress_tcp_request_timeout, 50}
        ]}
    ],
    application:set_env(AppConfig),
    ?assertMatch({ok, _}, erldns_pipeline_worker:start_link()),
    ?assertMatch({ok, _}, erldns_listeners:start_link()),
    _ = [
        spawn_link(fun bombard_tcp_fun/0)
     || _ <- lists:seq(1, erlang:system_info(schedulers))
    ],
    assert_telemetry_event(timeout).

udp_drop_packets(_) ->
    Iterations = 500,
    attach_to_telemetry(?FUNCTION_NAME, dropped, self()),
    Packet = packet(),
    AppConfig = [
        {erldns, [
            {listeners, [#{name => ?FUNCTION_NAME, transport => udp, port => 8053}]},
            {packet_pipeline, [fun pause_pipe/2]},
            {ingress_udp_request_timeout, 50}
        ]}
    ],
    application:set_env(AppConfig),
    ?assertMatch({ok, _}, erldns_pipeline_worker:start_link()),
    ?assertMatch({ok, _}, erldns_listeners:start_link()),
    {ok, Socket} = gen_udp:open(0, [binary, {active, false}]),
    [ok = gen_udp:send(Socket, {127, 0, 0, 1}, 8053, Packet) || _ <- lists:seq(1, Iterations)],
    assert_telemetry_event(dropped).

udp_load_shedding(_) ->
    attach_to_telemetry(?FUNCTION_NAME, delayed, self()),
    AppConfig = [
        {erldns, [
            {listeners, [#{name => ?FUNCTION_NAME, transport => udp, port => 8053}]},
            {packet_pipeline, [fun sleeping_pipe/2]},
            {ingress_udp_request_timeout, 50}
        ]}
    ],
    application:set_env(AppConfig),
    [spawn_link(fun waste_fun/0) || _ <- lists:seq(1, erlang:system_info(schedulers))],
    ?assertMatch({ok, _}, erldns_pipeline_worker:start_link()),
    ?assertMatch({ok, _}, erldns_listeners:start_link()),
    [spawn_link(fun bombard_udp_fun/0) || _ <- lists:seq(1, erlang:system_info(schedulers))],
    assert_telemetry_event(delayed).

tcp_load_shedding(_) ->
    attach_to_telemetry(?FUNCTION_NAME, delayed, self()),
    AppConfig = [
        {erldns, [
            {listeners, [#{name => ?FUNCTION_NAME, transport => tcp, port => 8053}]},
            {packet_pipeline, [fun sleeping_pipe/2]},
            {ingress_tcp_request_timeout, 50}
        ]}
    ],
    application:set_env(AppConfig),
    _ = [spawn_link(fun waste_fun/0) || _ <- lists:seq(1, erlang:system_info(schedulers))],
    ?assertMatch({ok, _}, erldns_pipeline_worker:start_link()),
    ?assertMatch({ok, _}, erldns_listeners:start_link()),
    _ = [
        spawn_link(fun bombard_tcp_fun/0)
     || _ <- lists:seq(1, erlang:system_info(schedulers))
    ],
    assert_telemetry_event(delayed).

udp_reactivate(_) ->
    Iterations = 5000,
    Packet = packet(),
    application:set_env(erldns, ingress_udp_request_timeout, 50),
    application:set_env(erldns, listeners, [
        #{name => ?FUNCTION_NAME, transport => udp, port => 8053}
    ]),
    application:set_env(erldns, packet_pipeline, []),
    ?assertMatch({ok, _}, erldns_pipeline_worker:start_link()),
    ?assertMatch({ok, _}, erldns_listeners:start_link()),
    {ok, Socket} = gen_udp:open(0, [binary, {active, false}]),
    [request_response(udp, Socket, Packet) || _ <- lists:seq(1, Iterations)].

udp_coverage(_) ->
    application:set_env(erldns, ingress_udp_request_timeout, 50),
    application:set_env(erldns, listeners, [
        #{name => ?FUNCTION_NAME, transport => udp, port => 8053}
    ]),
    ?assertMatch({ok, _}, erldns_listeners:start_link()),
    Children = supervisor:which_children(erldns_listeners),
    {_, Me, _, _} = lists:keyfind(?FUNCTION_NAME, 1, Children),
    [{_, AccSup, _, _}, {WorkersPool, _, _, _}] = supervisor:which_children(Me),
    [{_, AcceptorPid, _, _} | _] = supervisor:which_children(AccSup),
    gen_server:call(AcceptorPid, anything),
    gen_server:cast(AcceptorPid, anything),
    wpool:call(WorkersPool, anything, random_worker),
    wpool:cast(WorkersPool, anything, random_worker),
    wpool_pool:random_worker(WorkersPool) ! anything.

sched_mon_coverage(_) ->
    AppConfig = [
        {erldns, [
            {listeners, []},
            {packet_pipeline, []},
            {ingress_udp_request_timeout, 50}
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
    application:set_env(erldns, ingress_udp_request_timeout, 50),
    application:set_env(erldns, listeners, [
        #{name => ?FUNCTION_NAME, transport => tcp, port => 8053}
    ]),
    application:set_env(erldns, packet_pipeline, [fun bad_record/2]),
    ?assertMatch({ok, _}, erldns_pipeline_worker:start_link()),
    ?assertMatch({ok, _}, erldns_listeners:start_link()),
    {ok, Socket} = gen_tcp:connect(
        {127, 0, 0, 1}, 8053, [binary, {packet, 2}, {active, false}], 1000
    ),
    Response = request_response(tcp, Socket, Packet),
    ct:pal("Value ~p~n", [Response]),
    ?assertEqual(?DNS_RCODE_SERVFAIL, Response#dns_message.rc).

udp_encoder_failure(_) ->
    Packet = packet(),
    application:set_env(erldns, ingress_udp_request_timeout, 50),
    application:set_env(erldns, listeners, [
        #{name => ?FUNCTION_NAME, transport => udp, port => 8053}
    ]),
    application:set_env(erldns, packet_pipeline, [fun bad_record/2]),
    ?assertMatch({ok, _}, erldns_pipeline_worker:start_link()),
    ?assertMatch({ok, _}, erldns_listeners:start_link()),
    {ok, Socket} = gen_udp:open(0, [binary, {active, false}]),
    Response = request_response(udp, Socket, Packet),
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

pause_pipe(A, _) ->
    ct:sleep(35),
    A.

sleeping_pipe(A, _) ->
    ct:sleep(500),
    A.

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
