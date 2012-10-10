-module(erldns_udp_server).
-behavior(gen_server).

% API
-export([start_link/2]).

% Gen server hooks
-export([init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3
  ]).

-define(SERVER, ?MODULE).

-record(state, {port, socket}).

%% Public API
start_link(Name, InetFamily) ->
  gen_server:start_link({local, Name}, ?MODULE, [InetFamily], []).

%% gen_server hooks
init([InetFamily]) ->
  Port = erldns_config:get_port(),
  {ok, Socket} = start(Port, InetFamily),
  {ok, #state{port = Port, socket = Socket}}.
handle_call(_Request, _From, State) ->
  {ok, State}.
handle_cast(_Message, State) ->
  {noreply, State}.
handle_info({udp, Socket, Host, Port, Bin}, State) ->
  lager:debug("Received UDP Request ~p ~p ~p", [Socket, Host, Port]),
  poolboy:transaction(udp_worker_pool, fun(Worker) ->
    gen_server:call(Worker, {udp_query, Socket, Host, Port, Bin})
  end),
  % handle_dns_query(Socket, Host, Port, Bin),
  inet:setopts(State#state.socket, [{active, once}]),
  {noreply, State};
handle_info(_Message, State) ->
  {noreply, State}.
terminate(_Reason, _State) ->
  ok.
code_change(_PreviousVersion, State, _Extra) ->
  {ok, State}.

%% Internal functions
%% Start a UDP server.
start(Port, InetFamily) ->
  lager:info("Starting UDP server for ~p on port ~p~n", [InetFamily, Port]),
  case gen_udp:open(Port, [binary, {active, once}, {ip, erldns_config:get_address(InetFamily)}, InetFamily]) of
    {ok, Socket} -> 
      lager:info("UDP server (~p) opened socket: ~p~n", [InetFamily, Socket]),
      {ok, Socket};
    {error, eacces} ->
      lager:error("Failed to open UDP socket. Need to run as sudo?"),
      {error, eacces}
  end.
