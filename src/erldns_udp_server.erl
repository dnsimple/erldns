-module(erldns_udp_server).

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

%% Internal functions
%% Start a UDP server.
start(Port) ->
  random:seed(erlang:now()),
  case gen_udp:open(Port, [binary]) of
    {ok, Socket} -> 
      lager:info("UDP server opened socket: ~p~n", [Socket]),
      loop(Socket);
    {error, eacces} ->
      lager:error("Failed to open UDP socket. Need to run as sudo?"),
      {error, eacces}
  end.

%% Loop for accepting UDP requests
loop(Socket) ->
  lager:info("Awaiting Request~n"),
  receive
    {udp, Socket, Host, Port, Bin} ->
      lager:info("Received UDP Request~n"),
      spawn(fun() -> handle_dns_query(Socket, Host, Port, Bin) end),
      loop(Socket)
  end.

%% Handle DNS query that comes in over UDP
handle_dns_query(Socket, Host, Port, Bin) ->
  lager:info("Message from from ~p~n", [Host]),
  DecodedMessage = dns:decode_message(Bin),
  lager:info("Decoded message ~p~n", [DecodedMessage]),
  NewResponse = erldns_handler:handle(DecodedMessage),
  BinReply = dns:encode_message(NewResponse),
  gen_udp:send(Socket, Host, Port, BinReply).
