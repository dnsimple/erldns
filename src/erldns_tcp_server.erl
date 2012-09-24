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

-record(state, {port=53}).

%% Public API
start_link() ->
  gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% gen_server hooks
init(_Args) ->
  {ok, Port} = application:get_env(erldns, port),
  random:seed(erlang:now()),
  spawn_link(fun() -> start(Port, inet) end),
  spawn_link(fun() -> start(Port, inet6) end),
  {ok, #state{port=Port}}.
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
start(Port, InetFamily) ->
  lager:info("Starting TCP server for ~p on port ~p~n", [InetFamily, Port]),
  Options = [binary, InetFamily, {packet, 0}, {active, true}],
  case gen_tcp:listen(Port, Options) of
    {ok, LSocket} ->
      lager:info("TCP server (~p) opened listener: ~p~n", [InetFamily, LSocket]),
      loop(LSocket);
    {error, eacces} ->
      lager:error("Failed to open TCP listener. Need to run as sudo?"),
      {error, eacces}
  end.

%% Loop for accepting TCP requests
loop(LSocket) ->
  {ok, Socket} = gen_tcp:accept(LSocket),
  lager:debug("TCP server opened socket: ~p~n", [Socket]),
  receive
    {tcp, Socket, Bin} ->
      %% TODO: need the host IP for zone transfers
      lager:debug("Received TCP Request~n"),
      spawn_link(fun() -> handle_dns_query(Socket, Bin) end),
      loop(LSocket)
  end.

%% Handle DNS query that comes in over TCP
handle_dns_query(Socket, Packet) ->
  lager:debug("handle_dns_query(~p)", [Socket]),
  %% TODO: measure 
  <<_Len:16, Bin/binary>> = Packet,
  DecodedMessage = dns:decode_message(Bin),
  {ok, {Address, _Port}} = inet:peername(Socket),
  Response = erldns_handler:handle(DecodedMessage, Address),
  BinReply = erldns_encoder:encode_message(Response),
  BinLength = byte_size(BinReply),
  TcpBinReply = <<BinLength:16, BinReply/binary>>,
  gen_tcp:send(Socket, TcpBinReply),
  gen_tcp:close(Socket).
