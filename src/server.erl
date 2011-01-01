-module(server).
-include("include/nsrecs.hrl").
-export([start/0]).

-define(PORT, 8053).

start() ->
    start(?PORT).
start(Port) ->
    spawn(fun() -> udp_server(Port) end).

udp_server(Port) ->
    {ok, Socket} = gen_udp:open(Port, [binary]),
    io:format("Server opened socket: ~p~n", [Socket]),
    loop(Socket).

loop(Socket) ->
    io:format("Awaiting Request~n"),
    receive
        {udp, Socket, Host, Port, Bin} ->
            spawn(fun() -> handle_dns_query(Socket, Host, Port, Bin) end),
            loop(Socket)
    end.

handle_dns_query(Socket, Host, Port, Bin) ->
    io:format("Message from from ~p~n", [Host]),
    Request = unpack:unpack(Bin),
    Header = Request#message.header,
    Questions = Request#message.question,
    io:format("-- header --~n~p~n", [Header]),
    io:format("-- questions --~n"),
    lists:foreach(
        fun(Q) -> 
            io:format(" -> ~p~n", [Q#question.qname])
        end, 
        Questions),
    BinReply = Bin,
    gen_udp:send(Socket, Host, Port, BinReply).

