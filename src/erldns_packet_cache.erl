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

%% @doc A basic packet cache that is used to avoid multiple lookups for the
%% same question received within the cache TTL.
%%
%% The cache is swept for old cache data at regular intervals.
-module(erldns_packet_cache).

-behavior(gen_server).

% API
-export([start_link/0, get/1, get/2, put/2, sweep/0, clear/0]).

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
  get(Question, unknown).
get(Question, Host) ->
  gen_server:call(?SERVER, {get_packet, Question, Host}).
put(Question, Response) ->
  gen_server:call(?SERVER, {set_packet, [Question, Response]}).
sweep() ->
  gen_server:cast(?SERVER, {sweep, []}).
clear() ->
  gen_server:cast(?SERVER, {clear}).

%% Gen server hooks
init([]) ->
  init([20]);
init([TTL]) ->
  ets:new(packet_cache, [set, named_table]),
  {ok, Tref} = timer:apply_interval(?SWEEP_INTERVAL, ?MODULE, sweep, []),
  {ok, #state{ttl = TTL, tref = Tref}}.

handle_call({get_packet, Question, _Host}, _From, State) ->
  case ets:lookup(packet_cache, Question) of
    [{Question, {Response, ExpiresAt}}] ->
      {_,T,_} = erlang:now(),
      case T > ExpiresAt of
        true ->
          folsom_metrics:notify(cache_expired_meter, 1),
          {reply, {error, cache_expired}, State};
        false ->
          folsom_metrics:notify(cache_hit_meter, 1),
          {reply, {ok, Response}, State}
      end;
    _ ->
      folsom_metrics:notify(cache_miss_meter, 1),
      {reply, {error, cache_miss}, State}
  end;

handle_call({set_packet, [Question, Response]}, _From, State) ->
  {_,T,_} = erlang:now(),
  ets:insert(packet_cache, {Question, {Response, T + State#state.ttl}}),
  {reply, ok, State}.

handle_cast({sweep, []}, State) ->
  {_, T, _} = erlang:now(),
  Keys = ets:select(packet_cache, [{{'$1', {'_', '$2'}}, [{'<', '$2', T - 10}], ['$1']}]),
  lists:foreach(fun(K) -> ets:delete(packet_cache, K) end, Keys),
  {noreply, State};
handle_cast({clear}, State) ->
  ets:delete_all_objects(packet_cache),
  {noreply, State}.

handle_info(_Message, State) ->
  {noreply, State}.

terminate(_Reason, _State) ->
  ets:delete(packet_cache),
  ok.

code_change(_PreviousVersion, State, _Extra) ->
  {ok, State}.
