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
    {ok, _} = erpc:call(Node, application, ensure_all_started, [erldns]),
    {ok, _} = erpc:call(Node, erldns_storage, load_zones, []),
    Config.

get_node(Config) ->
    proplists:get_value(node, Config).

stop(Config) ->
    Pid = proplists:get_value(pid, Config),
    Pid ! stop.
