-module(erldns_packet_cache).

-behavior(gen_server).

% API
-export([start_link/0, get/1, put/2]).

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

get(Question) ->
  gen_server:call(?SERVER, {get_packet, Question}).
put(Question, Answer) ->
  gen_server:call(?SERVER, {set_packet, [Question, Answer]}).

%% Gen server hooks
init(_Args) ->
  ets:new(packet_cache, [set, named_table]),
  {ok, #state{}}.
handle_call({get_packet, Question}, _From, State) ->
  case ets:lookup(packet_cache, Question) of
    [{Question, {Answer, ExpiresAt}}] -> 
      {_,T,_} = erlang:now(),
      case T > ExpiresAt of
        true -> 
          lager:debug("Cache hit but expired"),
          {reply, {error, cache_expired}, State};
        false ->
          lager:debug("Time is ~p. Packet hit expires at ~p.", [T, ExpiresAt]),
          {reply, {ok, Answer}, State}
      end;
    _ -> {reply, {error, cache_miss}, State}
  end;
handle_call({set_packet, [Question, Answer]}, _From, State) ->
  {_,T,_} = erlang:now(),
  ets:insert(packet_cache, {Question, {Answer, T + 60}}),
  {reply, ok, State}.
handle_cast(_Message, State) ->
  {noreply, State}.
handle_info(_Message, State) ->
  {noreply, State}.
terminate(_Reason, _State) ->
  ets:delete(packet_cache),
  ok.
code_change(_PreviousVersion, State, _Extra) ->
  {ok, State}.
