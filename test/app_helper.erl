-module(app_helper).

-export([
    start_per_suite/2,
    start_per_testcase/2,
    stop/1,
    get_node/1,
    get_configured_port/3,
    reserve_port/0,
    attach_telemetry_remote/4
]).

-include_lib("common_test/include/ct.hrl").

-define(PEER_ATTEMPTS, 3).

%% Unlinked, so it outlives init_per_suite's process, which exits as soon as it
%% returns. Stop it with stop/1 from end_per_suite.
start_per_suite(Config, Env) ->
    {Peer, Node} = start_peer(1),
    true = unlink(Peer),
    do_start_erldns([{peer, Peer}, {node, Node} | Config], Env).

%% ?CT_PEER links the peer to the caller, so the node goes down with the test
%% case rather than lingering for the rest of the run.
start_per_testcase(Config, Env) ->
    {Peer, Node} = start_peer(1),
    do_start_erldns([{peer, Peer}, {node, Node} | Config], Env).

%% A failed boot exits the caller rather than returning an error.
start_peer(Attempt) ->
    try ?CT_PEER(#{args => ["+S", "2", "-pa" | code:get_path()], host => "127.0.0.1"}) of
        {ok, Peer, Node} -> {Peer, Node};
        {error, Reason} -> retry_peer(Reason, Attempt)
    catch
        exit:Reason -> retry_peer(Reason, Attempt)
    end.

retry_peer(Reason, ?PEER_ATTEMPTS) ->
    exit({peer, too_many_attempts, Reason});
retry_peer(Reason, Attempt) ->
    ct:pal("Peer start failed, retrying: ~p", [Reason]),
    ct:sleep(1000 * Attempt),
    start_peer(Attempt + 1).

stop(Config) ->
    peer:stop(proplists:get_value(peer, Config)).

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
            {_, Sup, _, _} = lists:keyfind({Name, udp}, 1, Children),
            {_, AccSup, _, _} = lists:keyfind(
                erldns_proto_udp_acceptor_sup, 1, supervisor:which_children(Sup)
            ),
            [{_, Acceptor, _, _} | _] = supervisor:which_children(AccSup),
            Socket = erldns_proto_udp_acceptor:get_socket(Acceptor),
            {ok, {_, Port}} = inet:sockname(Socket),
            Port
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

%% For listeners needing the same known port on UDP and TCP, where `port => 0'
%% would resolve a different one per protocol.
reserve_port() ->
    {ok, Socket} = gen_tcp:listen(0, [{active, false}]),
    {ok, Port} = inet:port(Socket),
    ok = gen_tcp:close(Socket),
    Port.

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
