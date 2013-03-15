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

% Internal API
-export([do_work/4, execute_transaction/5]).

-define(SERVER, ?MODULE).
-define(WORKER_TIMEOUT, 1000).

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
handle_info(timeout, State) ->
  lager:info("UDP instance timed out"),
  {noreply, State};
handle_info({udp, Socket, Host, Port, Bin}, State) ->
  [{message_queue_len, MailboxSize}] = erlang:process_info(self(),[message_queue_len]),
  lager:debug("Received UDP request ~p ~p ~p (mbsize: ~p)", [Socket, Host, Port, MailboxSize]),
  erldns_metrics:measure(Host, ?MODULE, do_work, [Socket, Host, Port, Bin]),
  inet:setopts(State#state.socket, [{active, once}]),
  lager:debug("Set active: once ~p ~p ~p", [Socket, Host, Port]),
  {noreply, State};
handle_info(Message, State) ->
  lager:debug("Received unknown message: ~p", [Message]),
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

do_work(Socket, Host, Port, Bin) ->
  poolboy:transaction(udp_worker_pool, worker_function(Socket, Host, Port, Bin), ?WORKER_TIMEOUT).

worker_function(Socket, Host, Port, Bin) ->
  fun(Worker) ->
    erldns_metrics:measure(Host, ?MODULE, execute_transaction, [Worker, Socket, Host, Port, Bin])
  end.

execute_transaction(Worker, Socket, Host, Port, Bin) ->
  lager:debug("Processing UDP with worker ~p ~p ~p", [Socket, Host, Port]),
  gen_server:call(Worker, {udp_query, Socket, Host, Port, Bin}),
  lager:debug("Completed UDP with worker ~p ~p ~p", [Socket, Host, Port]).
