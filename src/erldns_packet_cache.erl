-module(erldns_packet_cache).

-behavior(gen_server).

% API
-export([start_link/0, get/1, put/2, sweep/0]).

% Gen server hooks
-export([init/1,
	 handle_call/3,
	 handle_cast/2,
	 handle_info/2,
	 terminate/2,
	 code_change/3
       ]).

-define(SERVER, ?MODULE).
-define(SWEEP_INTERVAL, 1000 * 60 * 10). % Every 10 minutes

-record(state, {ttl, tref}).

%% Public API
start_link() ->
  gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

get(Question) ->
  gen_server:call(?SERVER, {get_packet, Question}).
put(Question, Response) ->
  gen_server:call(?SERVER, {set_packet, [Question, Response]}).
sweep() ->
  gen_server:cast(?SERVER, {sweep, []}).

%% Gen server hooks
init([]) ->
  init([20]);
init([TTL]) ->
  ets:new(packet_cache, [set, named_table]),
  {ok, Tref} = timer:apply_interval(?SWEEP_INTERVAL, ?MODULE, sweep, []),
  {ok, #state{ttl = TTL, tref = Tref}}.
handle_call({get_packet, Question}, _From, State) ->
  case ets:lookup(packet_cache, Question) of
    [{Question, {Response, ExpiresAt}}] ->
      {_,T,_} = erlang:now(),
      case T > ExpiresAt of
        true -> 
          lager:debug("Cache hit but expired"),
          {reply, {error, cache_expired}, State};
        false ->
          lager:debug("Time is ~p. Packet hit expires at ~p.", [T, ExpiresAt]),
          {reply, {ok, Response}, State}
      end;
    _ -> {reply, {error, cache_miss}, State}
  end;
handle_call({set_packet, [Question, Response]}, _From, State) ->
  {_,T,_} = erlang:now(),
  ets:insert(packet_cache, {Question, {Response, T + State#state.ttl}}),
  {reply, ok, State}.
handle_cast({sweep, []}, State) ->
  lager:debug("Sweeping packet cache"),
  {_, T, _} = erlang:now(),
  Keys = ets:select(packet_cache, [{{'$1', {'_', '$2'}}, [{'<', '$2', T - 10}], ['$1']}]),
  lager:debug("Found keys: ~p", [Keys]),
  lists:foreach(fun(K) -> ets:delete(packet_cache, K) end, Keys),
  {noreply, State}.
handle_info(_Message, State) ->
  {noreply, State}.
terminate(_Reason, _State) ->
  ets:delete(packet_cache),
  ok.
code_change(_PreviousVersion, State, _Extra) ->
  {ok, State}.
