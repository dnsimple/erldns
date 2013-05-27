-module(erldns_zoneserver_monitor).

-behavior(gen_server).

-export([start_link/0, connect/0, fetch_zones/0]).

-record(state, {}).

% Gen server hooks
-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3
  ]).

-define(SERVER, ?MODULE).
-define(INTERVAL, 5000).

%% Public API
start_link() ->
  gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

connect() ->
  gen_server:call(?SERVER, connect).

delay_connect() ->
  erlang:send_after(?INTERVAL, self(), connect).

fetch_zones() ->
  gen_server:call(?SERVER, fetch_zones).

delay_fetch_zones() ->
  erlang:send_after(?INTERVAL, self(), fetch_zones).

%% Gen server hooks
init([]) -> 
  {ok, #state{}}.

handle_call(connect, _From, State) ->
  do_connect(), 
  {reply, ok, State};

handle_call(fetch_zones, _From, State) ->
  do_fetch_zones(),
  {reply, ok, State}.

handle_cast(_, State) ->
  {noreply, State}.

handle_info({'EXIT', _Pid, {shutdown,{failed_to_start_child,websocket_client,econnrefused}}}, State) ->
  lager:info("Websocket failed to connect: connection was refused, retrying in ~p seconds", [?INTERVAL / 1000]),
  delay_connect(), 
  {noreply, State};

handle_info({'EXIT', _Pid, shutdown}, State) ->
  lager:info("Websocket connection failed, retrying in ~p seconds", [?INTERVAL / 1000]),
  delay_connect(), 
  {noreply, State};

handle_info(connect, State) ->
  do_connect(),
  {noreply, State};

handle_info(fetch_zones, State) ->
  do_fetch_zones(),
  {noreply, State}.

terminate(_Message, _State) ->
  lager:error("Terminated ~p", [?SERVER]),
  ok.

code_change(_, State, _) ->
  {ok, State}.

%% Internal API
do_connect() ->
  process_flag(trap_exit, true),
  WebsocketUrl = erldns_zone_client:websocket_url(),
  lager:debug("Connecting to web socket: ~p", [WebsocketUrl]),
  websocket_client:start_link(WebsocketUrl, erldns_zone_client, []).

do_fetch_zones() ->
  case erldns_zone_client:fetch_zones() of
    {err, Error} ->
      lager:error("Failed to fetch zones: ~p, retrying in ~p seconds", [Error, ?INTERVAL / 1000]),
      delay_fetch_zones();
    Result -> 
      Result 
  end.
