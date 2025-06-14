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
        udp_encoder_failure,
        tcp_encoder_failure,
        stats
    ].

-spec init_per_suite(ct_suite:ct_config()) -> ct_suite:ct_config().
init_per_suite(Config) ->
    application:ensure_all_started([ranch, worker_pool, telemetry]),
    Config.

-spec end_per_suite(ct_suite:ct_config()) -> term().
end_per_suite(_) ->
    [application:stop(App) || App <- [ranch, worker_pool, telemetry]].

-spec init_per_testcase(ct_suite:ct_testcase(), ct_suite:ct_config()) -> ct_suite:ct_config().
init_per_testcase(Drops, Config) when Drops =:= udp_drop_packets; Drops =:= tcp_drop_packets ->
    erlang:process_flag(trap_exit, true),
    erlang:system_flag(schedulers_online, 1),
    Config;
init_per_testcase(_, Config) ->
    erlang:process_flag(trap_exit, true),
    Config.

-spec end_per_testcase(ct_suite:ct_testcase(), ct_suite:ct_config()) -> term().
end_per_testcase(Drops, Config) when Drops =:= udp_drop_packets; Drops =:= tcp_drop_packets ->
    erlang:system_flag(schedulers_online, erlang:system_info(schedulers)),
    Config;
end_per_testcase(_, Config) ->
    Config.

%% Tests
name_must_be_atom(_) ->
    application:set_env(erldns, listeners, [#{}]),
    ?assertMatch({error, {{invalid_listener, name, #{}}, _}}, erldns_listeners:start_link()),
    application:set_env(erldns, listeners, [#{name => <<"bad">>}]),
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
    application:set_env(erldns, listeners, [#{name => ?FUNCTION_NAME, transport => <<"bad">>}]),
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
    TelemetryEventName = [erldns, request, timeout],
    ok = telemetry:attach(
        ?FUNCTION_NAME, TelemetryEventName, fun ?MODULE:telemetry_handler/4, self()
    ),
    Q = #dns_query{name = <<"example.com">>, type = ?DNS_TYPE_A},
    Msg = #dns_message{qc = 1, questions = [Q]},
    Packet = dns:encode_message(Msg),
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
    TelemetryEventName = [erldns, request, timeout],
    ok = telemetry:attach(
        ?FUNCTION_NAME, TelemetryEventName, fun ?MODULE:telemetry_handler/4, self()
    ),
    Q = #dns_query{name = <<"example.com">>, type = ?DNS_TYPE_A},
    Msg = #dns_message{qc = 1, questions = [Q]},
    Packet = dns:encode_message(Msg),
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
    Iterations = 500,
    TelemetryEventName = [erldns, request, timeout],
    ok = telemetry:attach(
        ?FUNCTION_NAME, TelemetryEventName, fun ?MODULE:telemetry_handler/4, self()
    ),
    Q = #dns_query{name = <<"example.com">>, type = ?DNS_TYPE_A},
    Msg = #dns_message{qc = 1, questions = [Q]},
    Packet = dns:encode_message(Msg),
    application:set_env(erldns, ingress_tcp_request_timeout, 50),
    application:set_env(erldns, listeners, [
        #{name => ?FUNCTION_NAME, transport => tcp, port => 8053}
    ]),
    application:set_env(erldns, packet_pipeline, [fun pause_pipe/2]),
    ?assertMatch({ok, _}, erldns_pipeline_worker:start_link()),
    ?assertMatch({ok, _}, erldns_listeners:start_link()),
    {ok, Socket1} = gen_tcp:connect(
        {127, 0, 0, 1}, 8053, [binary, {packet, 2}, {active, false}], 1000
    ),
    [ok = gen_tcp:send(Socket1, Packet) || _ <- lists:seq(1, Iterations)],
    assert_telemetry_event(timeout).

udp_drop_packets(_) ->
    Iterations = 500,
    TelemetryEventName = [erldns, request, dropped],
    ok = telemetry:attach(
        ?FUNCTION_NAME, TelemetryEventName, fun ?MODULE:telemetry_handler/4, self()
    ),
    Q = #dns_query{name = <<"example.com">>, type = ?DNS_TYPE_A},
    Msg = #dns_message{qc = 1, questions = [Q]},
    Packet = dns:encode_message(Msg),
    application:set_env(erldns, ingress_udp_request_timeout, 50),
    application:set_env(erldns, listeners, [
        #{name => ?FUNCTION_NAME, transport => udp, port => 8053}
    ]),
    application:set_env(erldns, packet_pipeline, [fun pause_pipe/2]),
    ?assertMatch({ok, _}, erldns_pipeline_worker:start_link()),
    ?assertMatch({ok, _}, erldns_listeners:start_link()),
    {ok, Socket} = gen_udp:open(0, [binary, {active, false}]),
    [ok = gen_udp:send(Socket, {127, 0, 0, 1}, 8053, Packet) || _ <- lists:seq(1, Iterations)],
    assert_telemetry_event(dropped).

udp_reactivate(_) ->
    Iterations = 5000,
    Q = #dns_query{name = <<"example.com">>, type = ?DNS_TYPE_A},
    Msg = #dns_message{qc = 1, questions = [Q]},
    Packet = dns:encode_message(Msg),
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

tcp_encoder_failure(_) ->
    Q = #dns_query{name = <<"example.com">>, type = ?DNS_TYPE_A},
    Msg = #dns_message{qc = 1, questions = [Q]},
    Packet = dns:encode_message(Msg),
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
    Q = #dns_query{name = <<"example.com">>, type = ?DNS_TYPE_A},
    Msg = #dns_message{qc = 1, questions = [Q]},
    Packet = dns:encode_message(Msg),
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
            M
    after 5000 ->
        ct:fail("Telemetry event not triggered")
    end.

pause_pipe(A, _) ->
    ct:sleep(35),
    A.

sleeping_pipe(A, _) ->
    ct:sleep(3000),
    A.

bad_record(A, _) ->
    A#dns_message{authority = [#dns_query{}]}.
