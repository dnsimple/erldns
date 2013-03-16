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
-export([do_work/5]).

-define(SERVER, ?MODULE).
-define(NUM_WORKERS, 10000).

-record(state, {port, socket, workers}).

%% Public API
start_link(Name, InetFamily) ->
  gen_server:start_link({local, Name}, ?MODULE, [InetFamily], []).

%% gen_server hooks
init([InetFamily]) ->
  Port = erldns_config:get_port(),
  {ok, Socket} = start(Port, InetFamily),
  {ok, #state{port = Port, socket = Socket, workers = make_workers(queue:new())}}.
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
  case queue:out(State#state.workers) of
    {{value, Worker}, Queue} ->
      erldns_metrics:measure(Host, ?MODULE, do_work, [Worker, Socket, Host, Port, Bin]),
      inet:setopts(State#state.socket, [{active, once}]),
      lager:debug("Processing UDP request ~p ~p ~p", [Socket, Host, Port]),
      {noreply, State#state{workers = queue:in(Worker, Queue)}};
    {empty, _Queue} ->
      lager:info("Queue is empty, dropping packet"),
      {noreply, State}
  end;
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
  lager:info("Starting UDP server for ~p on port ~p", [InetFamily, Port]),
  case gen_udp:open(Port, [binary, {active, once}, {read_packets, 1000}, {ip, erldns_config:get_address(InetFamily)}, InetFamily]) of
    {ok, Socket} -> 
      lager:info("UDP server (~p) opened socket: ~p", [InetFamily, Socket]),
      {ok, Socket};
    {error, eacces} ->
      lager:error("Failed to open UDP socket. Need to run as sudo?"),
      {error, eacces}
  end.

do_work(Worker, Socket, Host, Port, Bin) ->
  lager:debug("Casting udp query to worker ~p", [Worker]),
  gen_server:cast(Worker, {udp_query, Socket, Host, Port, Bin}).


make_workers(Queue) ->
  make_workers(Queue, 1).
make_workers(Queue, N) when N < ?NUM_WORKERS ->
  {ok, WorkerPid} = erldns_worker:start_link([]),
  make_workers(queue:in(WorkerPid, Queue), N + 1);
make_workers(Queue, _) ->
  Queue.
