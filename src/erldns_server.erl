-module(erldns_server).

-include("dns_records.hrl").

-behavior(gen_server).

% API
-export([start_link/0]).
-export([start/0, start/1]).

% Gen server hooks
-export([init/1,
	 handle_call/3,
	 handle_cast/2,
	 handle_info/2,
	 terminate/2,
	 code_change/3
       ]).

-define(SERVER, ?MODULE).
-define(PORT, 8053).

-record(state, {}).

%% Start the UDP and TCP servers
start() ->
  start(?PORT).
start(Port) ->
  application:start(mysql),

  spawn(fun() -> udp_server(Port) end),
  spawn(fun() -> tcp_server(Port) end).

start_link() ->
  gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% gen_server hooks
%% This is a work-in-progress
init(_Args) ->
  {ok, Port} = application:get_env(erldns, port),
  start(Port),
  {ok, #state{}}.
handle_call(_Request, _From, State) ->
  {ok, State}.
handle_cast(_Message, State) ->
  {noreply, State}.
handle_info(_Message, State) ->
  {noreply, State}.
terminate(_Reason, _State) ->
  ok.
code_change(_PreviousVersion, State, _Extra) ->
  {ok, State}.


%% Start a UDP server.
udp_server(Port) ->
  random:seed(erlang:now()),
  {ok, Socket} = gen_udp:open(Port, [binary]),
  io:format("UDP server opened socket: ~p~n", [Socket]),
  udp_loop(Socket).

%% Start a TCP server.
tcp_server(Port) ->
  random:seed(erlang:now()),
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
  DecodedMessage = dns:decode_message(Bin),
  NewResponse = answer_questions(DecodedMessage#dns_message.questions, DecodedMessage),
  BinReply = dns:encode_message(NewResponse),
  BinLength = byte_size(BinReply),
  TcpBinReply = <<BinLength:16, BinReply/binary>>,
  gen_tcp:send(Socket, TcpBinReply),
  gen_tcp:close(Socket).

%% Handle DNS query that comes in over UDP
handle_dns_query(Socket, Host, Port, Bin) ->
  io:format("Message from from ~p~n", [Host]),
  DecodedMessage = dns:decode_message(Bin),
  io:format("Decoded message ~p~n", [DecodedMessage]),
  NewResponse = answer_questions(DecodedMessage#dns_message.questions, DecodedMessage),
  BinReply = dns:encode_message(NewResponse),
  gen_udp:send(Socket, Host, Port, BinReply).

%% Answer the questions and return an updated copy of the given
%% Response.
answer_questions([], Response) ->
  Response;
answer_questions([Q|Rest], Response) ->
  io:format("Question: ~p~n", [Q]),
  NewResponse = answer_question(Q, Response),
  answer_questions(Rest, NewResponse).

%% Add answers for a specific request to the given Response and return
%% an updated copy of the Response.
answer_question(Q, Response) ->
  [Name, Type] = [Q#dns_query.name, Q#dns_query.type],

  ResponderModules = case application:get_env(erldns, responders) of
    {ok, RM} -> RM;
    _ -> [erldns_mysql_responder]
  end,

  Responders = lists:map(fun(M) -> fun M:answer/2 end, ResponderModules),

  Answers = lists:flatten(
    lists:map(
      fun(F) ->
          F(Name, dns:type_name(Type))
      end, Responders)),

  NewResponse = Response#dns_message{anc = length(Answers), aa = true, answers = Answers},
  io:format("Response: ~p~n", [NewResponse]),
  NewResponse.
