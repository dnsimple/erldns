%% Copyright (c) 2012-2013, Aetrion LLC
%%
%% Permission to use, copy, modify, and/or distribute this software for any
%% purpose with or without fee is hereby granted, provided that the above
%% copyright notice and this permission notice appear in all copies.
%%
%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
%% WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
%% MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
%% ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
%% WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
%% ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
%% OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

%% @doc Process for monitoring the state of zone server connections. Provides
%% a mechanism for retrying connections with the zone server instead of
%% causing the system to fail completely.
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

% Public API

%% Start the zone server monitor.
-spec start_link() -> any().
start_link() ->
  gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% @doc Attempt an immediate connection to the zone server.
-spec connect() -> any().
connect() ->
  gen_server:call(?SERVER, connect).

%% @doc Attempt a connection to the zone server after a delay (default: 5 seconds)
%% This is used after a failed connection to give the remote server time to recover
%% and to not flood it with unnecessary requests.
-spec delay_connect() -> any().
delay_connect() ->
  erlang:send_after(?INTERVAL, self(), connect).

%% @doc Fetch all zones from the zone server.
-spec fetch_zones() -> any().
fetch_zones() ->
  gen_server:call(?SERVER, fetch_zones, infinity).

%% @doc Fetch all zones from the zone server after a delay (default: 5 seconds)
-spec delay_fetch_zones() -> any().
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

handle_info({'EXIT', _Pid, normal}, State) ->
  folsom_metrics:notify(websocket_connection_terminated_meter, 1),
  lager:info("Websocket terminated normally, retrying in ~p seconds", [?INTERVAL / 1000]),
  delay_connect(),
  {noreply, State};

handle_info({'EXIT', _Pid, {shutdown,{failed_to_start_child,websocket_client,econnrefused}}}, State) ->
  folsom_metrics:notify(websocket_connection_refused_meter, 1),
  lager:info("Websocket failed to connect: connection was refused, retrying in ~p seconds", [?INTERVAL / 1000]),
  delay_connect(), 
  {noreply, State};

handle_info({'EXIT', _Pid, shutdown}, State) ->
  folsom_metrics:notify(websocket_connection_failed_meter, 1),
  lager:info("Websocket connection failed, retrying in ~p seconds", [?INTERVAL / 1000]),
  delay_connect(), 
  {noreply, State};

handle_info({'EXIT', _Pid, {error, close}}, State) ->
  folsom_metrics:notify(websocket_connection_closed_meter, 1),
  lager:info("Websocket closed connection, retrying in ~p seconds", [?INTERVAL / 1000]),
  delay_connect(),
  {noreply, State};

handle_info({'EXIT', _Pid, Message}, State) ->
  folsom_metrics:notify(websocket_connection_error_meter, 1),
  lager:error("Unknown error: ~p, retrying in ~p seconds", [Message, ?INTERVAL / 1000]),
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
      folsom_metrics:notify(fetch_zones_error_meter, 1),
      lager:error("Failed to fetch zones: ~p, retrying in ~p seconds", [Error, ?INTERVAL / 1000]),
      delay_fetch_zones();
    Result -> 
      Result 
  end.
