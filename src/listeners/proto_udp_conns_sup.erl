-module(proto_udp_conns_sup).

-include_lib("kernel/include/logger.hrl").

-export([start_udp/6]).
-export([start_link/2]).
-export([init/3]).

start_udp(Sup, Socket, Ip, Port, Bin, TS) ->
    Sup ! {?MODULE, start_udp, Socket, Ip, Port, Bin, TS}.

start_link(StatsCounters, Id) ->
    proc_lib:start_link(?MODULE, init, [StatsCounters, Id, self()]).

init(StatsCounters, Id, Parent) ->
    process_flag(trap_exit, true),
    proc_lib:set_label({?MODULE, Id}),
    ok = proc_lib:init_ack(Parent, {ok, self()}),
    ets:insert(erldns_listener, {{?MODULE, Id}, self()}),
    loop(StatsCounters, Id, Parent).

loop(StatsCounters, Id, Parent) ->
    receive
        {'EXIT', Parent, Reason} ->
            ?LOG_ERROR("Parent exits ~p:~p:~p~n", [self(), Parent, Reason]),
            ok;
        {'EXIT', _Pid, _Reason} ->
            inc_terminate(StatsCounters, Id, 1),
            loop(StatsCounters, Id, Parent);
        {?MODULE, start_udp, Socket, Ip, Port, Bin, TS} ->
            proto_udp_server:start_link(Socket, Ip, Port, Bin, TS),
            inc_accept(StatsCounters, Id, 1),
            loop(StatsCounters, Id, Parent);
        Msg ->
            ?LOG_ERROR("Msg ~p~n", [Msg]),
            loop(StatsCounters, Id, Parent)
    end.

inc_accept(StatsCounters, Id, N) ->
    %% Accepts are counted in the odd indexes.
    counters:add(StatsCounters, 2 * Id - 1, N).

inc_terminate(StatsCounters, Id, N) ->
    %% Terminates are counted in the even indexes.
    counters:add(StatsCounters, 2 * Id, N).
