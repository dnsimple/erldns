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

%% @doc Stateful counter that will send a server start event when the count
%% reaches 0
-module(erldns_zone_fetcher_countdown).

-behavior(gen_server).

-export([start_link/0, set_remaining/1, decrement/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-define(GC, true).

-record(state, {start, remaining}).

%% @doc Start the countdown process.
-spec start_link() -> any().
start_link() ->
  gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%% @doc Set the number of items that need to be fetched.
-spec set_remaining(non_neg_integer()) -> ok.
set_remaining(Remaining) ->
  gen_server:call(?MODULE, {set_remaining, Remaining}).

%% @doc Decrement the number of items remaining to be fetched.
-spec decrement() -> ok.
decrement() ->
  gen_server:cast(?MODULE, decrement).

% gen_server handlers

init(_) ->
  {ok, #state{}}.
handle_call({set_remaining, Remaining}, _, _) ->
  {reply, ok, #state{start = Remaining, remaining = Remaining}}.
handle_cast(decrement, State) ->
  case Remaining = State#state.remaining - 1 of
    0 ->
      erldns_events:notify(zone_fetcher_finished),
      lager:info("Loaded ~p zones", [State#state.start]),

      case ?GC of
        true ->
          erldns_sup:gc(),
          lager:info("GC complete");
        _ -> skipped
      end,

      {stop, normal, State#state{remaining = Remaining}};
    _ ->
      {noreply, State#state{remaining = Remaining}}
  end.
handle_info(_Info, State) ->
  {noreply, State}.
terminate(_Reason, _State) ->
  ok.
code_change(_OldVsn, State, _Extra) ->
  {ok, State}.
