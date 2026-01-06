-module(app_helper).
-compile([export_all, nowarn_export_all]).

-include_lib("common_test/include/ct.hrl").

start_erldns(Config, Env) ->
    Self = self(),
    Ref = make_ref(),
    {Pid, MonitorRef} = spawn_monitor(fun() ->
        Res = ?CT_PEER(["-pa" | code:get_path()]),
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
        {Ref, Other} ->
            exit(Other);
        {'DOWN', MonitorRef, _, _, _} ->
            exit({peer, died})
    after 10000 ->
        exit({peer, timeout})
    end.

do_start_erldns(Config, Env) ->
    Node = proplists:get_value(node, Config),
    ok = erpc:call(Node, application, set_env, [Env]),
    PrivDir = proplists:get_value(priv_dir, Config),
    File = filename:join([PrivDir, "dnstest.log"]),
    ct:pal("Log file ~n~s~n", [File]),
    ok = erpc:call(Node, logger, update_primary_config, [#{level => info}]),
    ok = erpc:call(Node, logger, add_handler, [dnstest, logger_std_h, #{config => #{file => File}}]),
    {ok, _} = erpc:call(Node, application, ensure_all_started, [erldns]),
    Config.

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
