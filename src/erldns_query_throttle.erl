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

%% @doc Stateful query throttling. Currently only throttles ANY queries.
%%
%% This throttling is useful for stopping DNS reflection/amplification attacks.
-module(erldns_query_throttle).

-behavior(gen_server).

-include_lib("dns/include/dns_records.hrl").

%% API
-export([start_link/0, throttle/2, sweep/0]).

% Gen server hooks
-export([init/1,
	 handle_call/3,
	 handle_cast/2,
	 handle_info/2,
	 terminate/2,
	 code_change/3
       ]).

%% Types
-export_type([throttle_result/0, throttle_hit_count/0]).
-type throttle_hit_count() :: non_neg_integer().
-type throttle_result() :: {throttled | ok, inet:ip_address() | inet:hostname(), throttle_hit_count()}.

-define(LIMIT, 5).
-define(EXPIRATION, 60).
-define(SWEEP_INTERVAL, 1000 * 60 * 10). % Every 10 minutes

-record(state, {tref}).

%% @doc Start the query throttle process.
-spec start_link() -> any().
start_link() ->
  gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%% @doc Throttle the given message if necessary.
-spec throttle(dns:message(), inet:ip_address() | inet:hostname()) -> ok | throttle_result().
throttle(Message, Host) ->
  gen_server:call(?MODULE, {throttle, Message, Host}).

%% @doc Sweep the query throttle table for expired host records.
-spec sweep() -> any().
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
  %lager:debug("Sweeping host throttle"),
  {_, T, _} = erlang:now(),
  Keys = ets:select(host_throttle, [{{'$1', {'_', '$2'}}, [{'<', '$2', T - ?EXPIRATION}], ['$1']}]),
  %lager:debug("Found keys: ~p", [Keys]),
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
  case ets:lookup(host_throttle, Host) of
    [{_, {ReqCount, LastRequestAt}}] -> 
      case is_throttled(Host, ReqCount, LastRequestAt) of
        {true, NewReqCount} -> {throttled, Host, NewReqCount};
        {false, NewReqCount} -> {ok, Host, NewReqCount}
      end;
    [] -> 
      {ok, Host, 1}
  end.

record_request({ThrottleResponse, Host, ReqCount}) ->
  {_, T, _} = erlang:now(),
  ets:insert(host_throttle, {Host, {ReqCount, T}}),
  {ThrottleResponse, Host, ReqCount}.

is_throttled({127,0,0,1}, ReqCount, _) -> {false, ReqCount + 1};
is_throttled(Host, ReqCount, LastRequestAt) ->
   {_,T,_} = erlang:now(),
   ExceedsLimit = ReqCount >= ?LIMIT,
   Expired = T - LastRequestAt > ?EXPIRATION,
   case Expired of
     true -> 
       ets:delete(host_throttle, Host),
       {false, 1};
     false -> 
       {ExceedsLimit, ReqCount + 1}
   end.
