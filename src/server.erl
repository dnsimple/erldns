-module(server).
-include("include/nsrecs.hrl").
-export([start/0, start/1]).

-define(PORT, 8053).

%% Start the UDP and TCP servers
start() ->
  start(?PORT).
start(Port) ->
  spawn(fun() -> udp_server(Port) end),
  spawn(fun() -> tcp_server(Port) end).

%% Start a UDP server.
udp_server(Port) ->
  {ok, Socket} = gen_udp:open(Port, [binary]),
  io:format("UDP server opened socket: ~p~n", [Socket]),
  udp_loop(Socket).

%% Start a TCP server.
tcp_server(Port) ->
  {ok, LSocket} = gen_tcp:listen(Port, [binary, {packet, 0}, {active, true}]),
  tcp_loop(LSocket).

%% Loop for accepting TCP requests
tcp_loop(LSocket) ->
  {ok, Socket} = gen_tcp:accept(LSocket),
  io:format("TCP server opened socket: ~p~n", [Socket]),
  receive
    {tcp, Socket, Bin} ->
      io:format("Received TCP Request~n"),
      spawn(fun() -> handle_dns_query(Socket, Bin) end),
      tcp_loop(LSocket)
  end.

%% Loop for accepting UDP requests
udp_loop(Socket) ->
  io:format("Awaiting Request~n"),
  receive
    {udp, Socket, Host, Port, Bin} ->
      io:format("Received UDP Request~n"),
      spawn(fun() -> handle_dns_query(Socket, Host, Port, Bin) end),
      udp_loop(Socket)
  end.

%% Handle DNS query that comes in over TCP
handle_dns_query(Socket, Packet) ->
  <<Len:16, Bin/binary>> = Packet,
  io:format("TCP Message received, len: ~p~n", [Len]),
  Request = inspect(unpack:unpack(Bin)),
  Response = build_response(Request),
  BinReply = rr:pack_message(Response),
  BinLength = byte_size(BinReply),
  TcpBinReply = <<BinLength:16, BinReply/binary>>,
  gen_tcp:send(Socket, TcpBinReply),
  gen_tcp:close(Socket).

%% Handle DNS query that comes in over UDP
handle_dns_query(Socket, Host, Port, Bin) ->
  io:format("Message from from ~p~n", [Host]),
  Request = inspect(unpack:unpack(Bin)),
  Response = build_response(Request),
  inspect(Response),
  BinReply = rr:pack_message(Response),
  gen_udp:send(Socket, Host, Port, BinReply).

%% Build the response message based on the request message.
build_response(Request) ->
  Answer = responder:answer(Request#message.question),
  #message{
    header = build_response_header(Request#message.header, Answer),
    question = Request#message.question,
    answer = Answer,
    authority = [],
    additional = []
  }.

%% Build the response header.
build_response_header(RequestHeader, Answer) ->
  #header{
    id      = RequestHeader#header.id,
    qr      = 1,
    opcode  = RequestHeader#header.opcode,
    aa      = 1,
    tc      = 0,
    rd      = RequestHeader#header.rd,
    ra      = 0,
    z       = 0,
    rcode   = 0,
    qdcount = RequestHeader#header.qdcount,
    ancount = length(Answer),
    nscount = 0,
    arcount = 0
  }.

%% Utility function for inspecting a DNS message.
inspect(Message) ->
  io:format("-- header --~n~p~n", [Message#message.header]),
  io:format("-- questions --~n"),
  lists:foreach(
    fun(Q) ->
        io:format(" -> ~p~n", [Q])
    end,
    Message#message.question),
  io:format("-- answers --~n"),
  lists:foreach(
    fun(A) ->
        io:format(" -> ~p~n", [A])
    end,
    Message#message.answer),
  io:format("-- authority --~n"),
  lists:foreach(
    fun(A) ->
        io:format(" -> ~p~n", [A])
    end,
    Message#message.authority),
  io:format("-- additional --~n"),
  lists:foreach(
    fun(A) ->
        io:format(" -> ~p~n", [A])
    end,
    Message#message.additional),
  Message.
