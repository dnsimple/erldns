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

%% @doc Application event handler implementation.
-module(erldns_event_handler).

-behavior(gen_event).

-export([
    init/1,
    handle_event/2,
    handle_call/2,
    handle_info/2,
    code_change/3,
    terminate/2
  ]).

-record(state, {servers_running = false}).

init(_Args) ->
  {ok, #state{}}.

handle_event(start_servers, State) ->
  case State#state.servers_running of
    false ->
      % Start up the UDP and TCP servers
      lager:debug("Starting the UDP and TCP supervisor"),
      erldns_server_sup:start_link(),
      %lager:debug("Starting the run checker"),
      %erldns_zone_cache:run_checker(),
      erldns_events:notify(servers_started),
       {ok, State#state{servers_running = true}};
    _ ->
       {ok, State}
  end;

handle_event(zone_fetcher_finished, State) ->
  erldns_events:notify(start_servers),
  {ok, State};

handle_event(Event, State) ->
  lager:debug("Unhandled event: ~p", [Event]),
  {ok, State}.

handle_call(_Message, State) ->
  {ok, ok, State}.

handle_info(_Message, State) ->
  {ok, State}.

code_change(_OldVsn, State, _Extra) ->
  {ok, State}.
 
terminate(_Reason, _State) ->
  ok.
