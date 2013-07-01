-module(erldns_event_logger).

-behavior(gen_event).

-export([
    init/1,
    handle_event/2,
    handle_call/2,
    handle_info/2,
    code_change/3,
    terminate/2
  ]).

-record(state, {}).

init(_Args) ->
  {ok, #state{}}.

handle_event(Event, State) ->
  lager:debug("Received event: ~p", [Event]),
  {ok, State}.

handle_call(_Message, State) ->
  {ok, ok, State}.

handle_info(_Message, State) ->
  {ok, State}.

code_change(_OldVsn, State, _Extra) ->
  {ok, State}.
 
terminate(_Reason, _State) ->
  ok.
