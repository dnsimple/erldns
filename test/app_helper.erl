-module(app_helper).
-compile([export_all, nowarn_export_all]).

-include_lib("common_test/include/ct.hrl").

start_peer(Config) ->
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
            [{pid, Pid}, {peer, Peer}, {node, Node} | Config];
        {Ref, Other} ->
            exit(Other);
        {'DOWN', MonitorRef, _, _, _} ->
            exit({peer, died})
    after 10000 ->
        exit({peer, timeout})
    end.

start_erldns(Config, Env) ->
    Node = proplists:get_value(node, Config),
    ok = erpc:call(Node, application, set_env, [Env]),
    PrivDir = proplists:get_value(priv_dir, Config),
    File = filename:join([PrivDir, "dnstest.log"]),
    ct:pal("Log file ~p~n", [File]),
    ok = erpc:call(Node, logger, update_primary_config, [#{level => info}]),
    ok = erpc:call(Node, logger, add_handler, [dnstest, logger_std_h, #{config => #{file => File}}]),
    {ok, _} = erpc:call(Node, application, ensure_all_started, [erldns]),
    {ok, _} = erpc:call(Node, erldns_storage, load_zones, []),
    ok.

get_node(Config) ->
    proplists:get_value(node, Config).

stop(Config) ->
    Pid = proplists:get_value(pid, Config),
    Pid ! stop.
