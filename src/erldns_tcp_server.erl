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
-define(DEFAULT_IPV4_ADDRESS, {127,0,0,1}).
-define(DEFAULT_IPV6_ADDRESS, {0,0,0,0,0,0,0,1}).
-define(DEFAULT_PORT, 53).

-record(state, {port=?DEFAULT_PORT, socket}).

%% Public API
start_link(_Name, inet) ->
  gen_nb_server:start_link(?MODULE, get_address(inet4) , get_port(), []);
start_link(_Name, inet6) ->
  gen_nb_server:start_link(?MODULE, get_address(inet6) , get_port(), []).

%% gen_server hooks
init([]) ->
  {ok, #state{}}.
handle_call(_Request, _From, State) ->
  {ok, State}.
handle_cast(_Message, State) ->
  {noreply, State}.
handle_info({tcp, Socket, Bin}, State) ->
  poolboy:transaction(tcp_worker_pool, fun(Worker) ->
    gen_server:call(Worker, {tcp_query, Socket, Bin})
  end),
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

%% Private functions
get_address(inet4) ->
  case application:get_env(erldns, inet4) of
    {ok, Address} -> Address;
    _ -> ?DEFAULT_IPV4_ADDRESS
  end;
get_address(inet6) ->
  case application:get_env(erldns, inet6) of
    {ok, Address} -> Address;
    _ -> ?DEFAULT_IPV6_ADDRESS
  end.

get_port() ->
  case application:get_env(erldns, port) of
    {ok, Port} -> Port;
    _ -> ?DEFAULT_PORT
  end.

