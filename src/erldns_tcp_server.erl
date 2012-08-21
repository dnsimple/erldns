-module(erldns_tcp_server).

-behavior(gen_server).

% API
-export([start_link/0]).

% Gen server hooks
-export([init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3
  ]).

-define(SERVER, ?MODULE).

-record(state, {}).

%% Public API
start_link() ->
  gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% gen_server hooks
init(_Args) ->
  {ok, Port} = application:get_env(erldns, port),
  spawn(fun() -> start(Port) end),
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

%% Internal API
%% Start the TCP server.
start(Port) ->
  random:seed(erlang:now()),
  case gen_tcp:listen(Port, [binary, {packet, 0}, {active, true}]) of
    {ok, LSocket} ->
      lager:info("TCP server opened listener: ~p~n", [LSocket]),
      loop(LSocket);
    {error, eacces} ->
      lager:error("Failed to open TCP listener. Need to run as sudo?"),
      {error, eacces}
  end.

%% Loop for accepting TCP requests
loop(LSocket) ->
  {ok, Socket} = gen_tcp:accept(LSocket),
  lager:info("TCP server opened socket: ~p~n", [Socket]),
  receive
    {tcp, Socket, Bin} ->
      io:format("Received TCP Request~n"),
      spawn(fun() -> handle_dns_query(Socket, Bin) end),
      loop(LSocket)
  end.

%% Handle DNS query that comes in over TCP
handle_dns_query(Socket, Packet) ->
  <<Len:16, Bin/binary>> = Packet,
  lager:info("TCP Message received, len: ~p~n", [Len]),
  DecodedMessage = dns:decode_message(Bin),
  NewResponse = erldns_handler:handle(DecodedMessage),
  BinReply = dns:encode_message(NewResponse),
  BinLength = byte_size(BinReply),
  TcpBinReply = <<BinLength:16, BinReply/binary>>,
  gen_tcp:send(Socket, TcpBinReply),
  gen_tcp:close(Socket).
