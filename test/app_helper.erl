-module(app_helper).
-compile([export_all, nowarn_export_all]).

-include_lib("common_test/include/ct.hrl").

-define(PEER_ATTEMPTS, 3).
% 30 seconds for CI environments
-define(PEER_STARTUP_TIMEOUT, 30000).

start_erldns(Config, Env) ->
    start_erldns(Config, Env, 1).

start_erldns(_, _, Attempt) when Attempt =:= ?PEER_ATTEMPTS + 1 ->
    exit({peer, too_many_attempts});
start_erldns(Config, Env, Attempt) ->
    ct:pal("Attempting to create peer (attempt ~p/~p)", [Attempt, ?PEER_ATTEMPTS]),
    Self = self(),
    Ref = make_ref(),
    {Pid, MonitorRef} = spawn_monitor(fun() ->
        StartTime = erlang:monotonic_time(microsecond),
        Res = ?CT_PEER(["+S 2 -pa" | code:get_path()]),
        Elapsed = erlang:monotonic_time(microsecond) - StartTime,
        ct:pal("Peer node created in ~p ms", [Elapsed / 1000]),
        Self ! {Ref, Res},
        receive
            stop ->
                ok
        end
    end),
    receive
        {Ref, {ok, Peer, Node}} ->
            erlang:demonitor(MonitorRef, [flush]),
            NewConfig = [{pid, Pid}, {peer, Peer}, {node, Node} | Config],
            do_start_erldns(NewConfig, Env);
        {Ref, {error, Reason}} ->
            erlang:demonitor(MonitorRef, [flush]),
            ct:pal("Peer process died: ~p", [Reason]),
            ct:sleep(1000 * Attempt),
            start_erldns(Config, Env, Attempt + 1);
        {'DOWN', MonitorRef, _, Pid, Reason} ->
            erlang:demonitor(MonitorRef, [flush]),
            ct:pal("Peer process died: ~p", [Reason]),
            ct:sleep(1000 * Attempt),
            start_erldns(Config, Env, Attempt + 1)
    after ?PEER_STARTUP_TIMEOUT ->
        erlang:demonitor(MonitorRef, [flush]),
        erlang:is_process_alive(Pid) andalso exit(Pid, kill),
        ct:pal("Peer process timed-out"),
        ct:sleep(1000 * Attempt),
        start_erldns(Config, Env, Attempt + 1)
    end.

do_start_erldns(Config, Env) ->
    Node = proplists:get_value(node, Config),
    ok = erpc:call(Node, application, set_env, [Env]),
    PrivDir = proplists:get_value(priv_dir, Config),
    UniqueInt = erlang:unique_integer([positive, monotonic]),
    File = filename:join([PrivDir, integer_to_list(UniqueInt) ++ "dnstest.log"]),
    ct:pal("Log file ~n~s~n", [File]),
    ok = erpc:call(Node, logger, update_primary_config, [#{level => info}]),
    ok = erpc:call(Node, logger, add_handler, [dnstest, logger_std_h, #{config => #{file => File}}]),
    {ok, _} = erpc:call(Node, application, ensure_all_started, [erldns]),
    Config.

get_configured_port(Config, Name, udp) ->
    Node = app_helper:get_node(Config),
    erpc:call(Node, fun() ->
        try
            Children = supervisor:which_children(erldns_listeners),
            case lists:keyfind({Name, udp}, 1, Children) of
                {_, Sup, _, _} ->
                    ChildSpecs = supervisor:which_children(Sup),
                    case ChildSpecs of
                        [{erldns_proto_udp_acceptor_sup, AccSup, _, _} | _] ->
                            AccChildren = supervisor:which_children(AccSup),
                            case AccChildren of
                                [{_, AcceptorPid, _, _} | _] ->
                                    State = sys:get_state(AcceptorPid),
                                    Socket = element(3, State),
                                    {ok, {_, Port}} = inet:sockname(Socket),
                                    Port;
                                _ ->
                                    error(no_udp_acceptor)
                            end;
                        _ ->
                            error(no_udp_acceptor_sup)
                    end;
                _ ->
                    error(no_udp_listener)
            end
        catch
            _:Reason ->
                error({failed_to_get_udp_port, Reason})
        end
    end);
get_configured_port(Config, Name, tcp) ->
    Node = app_helper:get_node(Config),
    erpc:call(Node, ranch, get_port, [{erldns_listeners, {Name, tcp}}]);
get_configured_port(Config, Name, tls) ->
    Node = app_helper:get_node(Config),
    erpc:call(Node, ranch, get_port, [{erldns_listeners, {Name, tls}}]);
get_configured_port(_Config, _, standard) ->
    0.

get_node(Config) ->
    proplists:get_value(node, Config).

stop(Config) ->
    Pid = proplists:get_value(pid, Config),
    Pid ! stop.

%% Attach telemetry handler on peer node that forwards events to test node
attach_telemetry_remote(Node, Name, Types, TestPid) when is_list(Types) ->
    % Create handler function on remote node to avoid serialization issues
    % with closures. The handler forwards events to the test node's Pid.
    ok = erpc:call(Node, fun() ->
        Handler = fun(EventName, Measurements, Metadata, _) ->
            % Forward event to test node
            TestPid ! {EventName, Measurements, Metadata}
        end,
        Events = [[erldns, request, Type] || Type <- Types],
        telemetry:attach_many(Name, Events, Handler, [])
    end);
attach_telemetry_remote(Node, Name, Type, TestPid) ->
    attach_telemetry_remote(Node, Name, [Type], TestPid).
