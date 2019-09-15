%% Copyright (c) 2012-2018, DNSimple Corporation
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
-export([start_link/0, throttle/2, sweep/0, stop/0]).

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

-define(LIMIT, 1).
-define(EXPIRATION, 60).
-define(ENABLED, true).
-define(SWEEP_INTERVAL, 1000 * 60 * 5).

-record(state, {tref}).

%% @doc Start the query throttle process.
-spec start_link() -> any().
start_link() ->
  gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%% @doc Throttle the given message if necessary.
-spec throttle(dns:message(), Context :: {term(), Host :: inet:ip_address() | inet:hostname()}) ->
  ok | throttle_result().
-if(not(ENABLED)).
throttle(_Message, {_, _Host}) ->
    %% lager:debug("Throttle not enabled"),
    ok.
-else.
throttle(_Message, {tcp, _Host}) ->
  ok;
throttle(Message, {_, Host}) ->
    case lists:filter(fun(Q) -> Q#dns_query.type =:= ?DNS_TYPE_ANY end, Message#dns_message.questions) of
        [] -> ok;
        _ -> record_request(maybe_throttle(Host))
    end.

%% Internal
-spec(maybe_throttle(inet:ip_address() | inet:hostname()) -> throttle_result()).
maybe_throttle(Host) ->
  case erldns_storage:select(host_throttle, Host) of
    [{_, {ReqCount, LastRequestAt}}] ->
      case is_throttled(Host, ReqCount, LastRequestAt) of
        {true, NewReqCount} -> {throttled, Host, NewReqCount};
        {false, NewReqCount} -> {ok, Host, NewReqCount}
      end;
    [] ->
      {ok, Host, 1}
  end.

-spec(record_request(throttle_result()) -> throttle_result()).
record_request(Res = {_ThrottleResponse, Host, ReqCount}) ->
  erldns_storage:insert(host_throttle, {Host, {ReqCount, timestamp()}}),
  Res.

is_throttled({127,0,0,1}, ReqCount, _) -> {false, ReqCount + 1};
is_throttled(Host, ReqCount, LastRequestAt) ->
  ExceedsLimit = ReqCount >= ?LIMIT,
  Expired = timestamp() - LastRequestAt > ?EXPIRATION,
  case Expired of
    true ->
      erldns_storage:delete(host_throttle, Host),
      {false, 1};
    false ->
      {ExceedsLimit, ReqCount + 1}
  end.
-endif.

%% @doc Sweep the query throttle table for expired host records.
-spec sweep() -> any().
sweep() ->
  gen_server:cast(?MODULE, sweep).

%% @doc Stop the query throttle process normally.
-spec stop() -> any().
stop() ->
  gen_server:call(?MODULE, stop).


% Gen server hooks
init([]) ->
  erldns_storage:create(host_throttle),
  {ok, Tref} = timer:apply_interval(?SWEEP_INTERVAL, ?MODULE, sweep, []),
  {ok, #state{tref = Tref}}.

handle_call(stop, _From, State) ->
  {stop, normal, ok, State}.

handle_cast(sweep, State) ->
  Keys = erldns_storage:select(host_throttle, [{{'$1', {'_', '$2'}}, [{'<', '$2', timestamp() - ?EXPIRATION}], ['$1']}], infinite),
  lists:foreach(fun(K) -> erldns_storage:delete(host_throttle, K) end, Keys),
  {noreply, State}.

handle_info(_Message, State) ->
  {noreply, State}.

terminate(_Reason, _State) ->
  erldns_storage:delete_table(host_throttle),
  ok.

code_change(_PreviousVersion, State, _Extra) ->
  {ok, State}.

%% Internal API

timestamp() ->
  {TM, TS, _} = os:timestamp(),
  (TM * 1000000) + TS.
