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

% Internal API
-export([handle_request/2]).

-define(SERVER, ?MODULE).

-record(state, {port, socket}).

%% Public API
start_link(_Name, Family) ->
  Port = erldns_config:get_port(),
  lager:info("Starting TCP server for ~p on port ~p", [Family, Port]),
  gen_nb_server:start_link(?MODULE, erldns_config:get_address(Family), Port, []).

%% gen_server hooks
init([]) ->
  {ok, #state{}}.
handle_call(_Request, _From, State) ->
  {ok, State}.
handle_cast(_Message, State) ->
  {noreply, State}.
handle_info({tcp, Socket, Bin}, State) ->
  folsom_metrics:histogram_timed_update(tcp_handoff_histogram, ?MODULE, handle_request, [Socket, Bin]),
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

handle_request(Socket, Bin) ->
  poolboy:transaction(tcp_worker_pool, fun(Worker) ->
    gen_server:call(Worker, {tcp_query, Socket, Bin})
  end).
