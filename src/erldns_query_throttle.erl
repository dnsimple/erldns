-module(erldns_query_throttle).

-behavior(gen_server).

-include("dns_records.hrl").

% API
-export([start_link/0, throttle/2, sweep/0]).

% Gen server hooks
-export([init/1,
	 handle_call/3,
	 handle_cast/2,
	 handle_info/2,
	 terminate/2,
	 code_change/3
       ]).

-define(LIMIT, 5).
-define(EXPIRATION, 60).
-define(SWEEP_INTERVAL, 1000 * 60 * 10). % Every 10 minutes

-record(state, {tref}).

% API
start_link() ->
  gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

throttle(Message, Host) ->
  gen_server:call(?MODULE, {throttle, Message, Host}).
sweep() ->
  gen_server:cast(?MODULE, {sweep}).

% Gen server hooks
init([]) ->
  ets:new(host_throttle, [set, named_table]),
  {ok, Tref} = timer:apply_interval(?SWEEP_INTERVAL, ?MODULE, sweep, []),
  {ok, #state{tref = Tref}}.

handle_call({throttle, Message, Host}, _From, State) ->
  case lists:filter(fun(Q) -> Q#dns_query.type =:= ?DNS_TYPE_ANY end, Message#dns_message.questions) of
    [] -> {reply, ok, State};
    _ -> {reply, record_request(maybe_throttle(Host)), State}
  end.

handle_cast({sweep}, State) ->
  lager:debug("Sweeping host throttle"),
  {_, T, _} = erlang:now(),
  Keys = ets:select(host_throttle, [{{'$1', {'_', '$2'}}, [{'<', '$2', T - ?EXPIRATION}], ['$1']}]),
  lager:debug("Found keys: ~p", [Keys]),
  lists:foreach(fun(K) -> ets:delete(host_throttle, K) end, Keys),
  {noreply, State}.

handle_info(_Message, State) ->
  {noreply, State}.

terminate(_Reason, _State) ->
  ets:delete(host_throttle),
  ok.

code_change(_PreviousVersion, State, _Extra) ->
  {ok, State}.

% Internal API
maybe_throttle(Host) ->
  lager:debug("maybe_throttle(~p)", [Host]),
  case ets:lookup(host_throttle, Host) of
    [{_, {ReqCount, LastRequestAt}}] -> 
      lager:debug("Throttle record found: ReqCount: ~p, LastRequestAt: ~p", [ReqCount, LastRequestAt]),
      case is_throttled(Host, ReqCount, LastRequestAt) of
        {true, NewReqCount} -> {throttled, Host, NewReqCount};
        {false, NewReqCount} -> {ok, Host, NewReqCount}
      end;
    [] -> 
      lager:debug("No throttle record found."),
      {ok, Host, 1}
  end.

record_request({ThrottleResponse, Host, ReqCount}) ->
  {_, T, _} = erlang:now(),
  lager:debug("Recording request for ~p {~p, ~p}", [Host, ReqCount, T]),
  ets:insert(host_throttle, {Host, {ReqCount, T}}),
  {ThrottleResponse, Host, ReqCount}.

is_throttled({127,0,0,1}, ReqCount, _) -> {false, ReqCount + 1};
is_throttled(Host, ReqCount, LastRequestAt) ->
   {_,T,_} = erlang:now(),
   ExceedsLimit = ReqCount >= ?LIMIT,
   Expired = T - LastRequestAt > ?EXPIRATION,
   lager:debug("exceeds limit? ~p expired? ~p", [ExceedsLimit, Expired]),
   lager:debug("is throttled? ~p", [(not Expired) and ExceedsLimit]),
   lager:debug("expires at: ~p", [LastRequestAt + ?EXPIRATION]),
   case Expired of
     true -> 
       ets:delete(host_throttle, Host),
       lager:debug("after delete: ~p", [ets:lookup(host_throttle, Host)]),
       {false, 1};
     false -> 
       {ExceedsLimit, ReqCount + 1}
   end.
