-module(erldns_tcp_server).

-behavior(gen_nb_server).

% API
-export([start_link/2]).

% Gen server hooks
-export([init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    sock_opts/0,
    new_connection/2,
    code_change/3
  ]).

-define(SERVER, ?MODULE).

-record(state, {port=53, socket}).

%% Public API
start_link(_Name, inet) ->
  {ok, Port} = application:get_env(erldns, port),
  gen_nb_server:start_link(?MODULE, {0,0,0,0} , Port, []);
start_link(_Name, inet6) ->
  {ok, Port} = application:get_env(erldns, port),
  gen_nb_server:start_link(?MODULE, {0,0,0,0,0,0,0,0} , Port, []).

%% gen_server hooks
init([]) ->
  {ok, #state{}}.
handle_call(_Request, _From, State) ->
  {ok, State}.
handle_cast(_Message, State) ->
  {noreply, State}.
handle_info({tcp, Socket, Bin}, State) ->
  handle_dns_query(Socket, Bin),
  {noreply, State};
handle_info(_Message, State) ->
  {noreply, State}.
terminate(_Reason, _State) ->
  ok.
sock_opts() ->
  [binary].
new_connection(Socket, State) ->
  inet:setopts(Socket, [{active, once}]),
  {ok, State}.
code_change(_PreviousVersion, State, _Extra) ->
  {ok, State}.

%% Handle DNS query that comes in over TCP
handle_dns_query(Socket, Packet) ->
  lager:debug("handle_dns_query(~p)", [Socket]),
  %% TODO: measure 
  <<_Len:16, Bin/binary>> = Packet,
  {ok, {Address, _Port}} = inet:peername(Socket),
  case Bin of
    <<>> -> ok;
    _ ->
      DecodedMessage = dns:decode_message(Bin),
      Response = erldns_handler:handle(DecodedMessage, Address),
      BinReply = erldns_encoder:encode_message(Response),
      BinLength = byte_size(BinReply),
      TcpBinReply = <<BinLength:16, BinReply/binary>>,
      gen_tcp:send(Socket, TcpBinReply)
  end,
  gen_tcp:close(Socket).
