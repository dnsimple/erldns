-module(proto_udp_wpool_acceptor).

-include_lib("kernel/include/logger.hrl").

-export([start_link/4]).
-export([init/4]).

start_link(AcceptorId, Port, Parent, Ref) ->
	proc_lib:start_link(?MODULE, init, [Ref, AcceptorId, Port, Parent]).

init(Ref, AcceptorId, Port, Parent) ->
    Workers = ets:lookup_element(erldns_listener, workers, 2),
	Socket = create_socket(Port),
    process_flag(trap_exit, true),
    proc_lib:set_label({?MODULE, AcceptorId}),
    proc_lib:init_ack(Parent, {ok, self()}),
    loop(Ref, Workers, AcceptorId, Socket, Parent).

loop(Ref, Workers, AcceptorId, Socket, Parent) ->
    receive
        {udp, Socket, Ip, Port, Bin} ->
            TS = erlang:monotonic_time(),
            proto_worker_pool:give_to_worker(Ref, Workers, {Socket, Ip, Port, Bin, TS}),
            loop(Ref, Workers, AcceptorId, Socket, Parent);
        {udp_passive, Socket} ->
            inet:setopts(Socket, [{active, 100}]),
            loop(Ref, Workers, AcceptorId, Socket, Parent);
        {'EXIT', Parent, Reason} ->
            ?LOG_NOTICE("Parent exits ~p:~p:~p~n", [self(), Parent, Reason]);
        Msg ->
            ?LOG_ERROR("Unknown message ~p~n", [Msg]),
            loop(Ref, Workers, AcceptorId, Socket, Parent)
    end.

-spec create_socket(inet:port_number()) -> inet:socket().
create_socket(Port) ->
    Ip = {0, 0, 0, 0},
    Opts = [
        inet,
        binary,
        {ip, Ip},
        {port, Port},
        {active, 100},
        {reuseaddr, true},
        {reuseport, true},
        {reuseport_lb, true},
        {read_packets, 1000},
        {recbuf, 1024 * 1024}
    ],
    case gen_udp:open(Port, Opts) of
        {ok, Socket} ->
            Socket;
        {error, Reason} ->
            exit(Reason)
    end.
