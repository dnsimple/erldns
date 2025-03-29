-module(proto_udp_acceptor).

-include_lib("kernel/include/logger.hrl").

-export([start_link/3]).
-export([init/3]).

start_link(AcceptorId, Port, Parent) ->
	proc_lib:start_link(?MODULE, init, [AcceptorId, Port, Parent]).

init(AcceptorId, Port, Parent) ->
	ConnsSup = ets:lookup_element(erldns_listener, {proto_udp_conns_sup, AcceptorId}, 2),
	MonitorRef = monitor(process, ConnsSup),
	Socket = create_socket(Port),
    process_flag(trap_exit, true),
    proc_lib:set_label({?MODULE, AcceptorId}),
    proc_lib:init_ack(Parent, {ok, self()}),
    loop(AcceptorId, Socket, Parent, ConnsSup, MonitorRef).

loop(AcceptorId, Socket, Parent, ConnsSup, MonitorRef) ->
    receive
        {'EXIT', Parent, Reason} ->
            ?LOG_ERROR("Parent exits ~p:~p:~p~n", [self(), Parent, Reason]),
            ok;
        {udp, Socket, Ip, Port, Bin} ->
            TS = erlang:monotonic_time(),
            proto_udp_conns_sup:start_udp(ConnsSup, Socket, Ip, Port, Bin, TS),
            loop(AcceptorId, Socket, Parent, ConnsSup, MonitorRef);
        {udp_passive, Socket} ->
            inet:setopts(Socket, [{active, 100}]),
            loop(AcceptorId, Socket, Parent, ConnsSup, MonitorRef);
        Msg ->
            ?LOG_ERROR("Unknown message ~p~n", [Msg]),
            loop(AcceptorId, Socket, Parent, ConnsSup, MonitorRef)
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
