-module(erldns_events).

-export([start_link/0, notify/1, add_handler/1, add_handler/2]).

start_link() ->
  gen_event:start_link({local, ?MODULE}).

notify(Event) ->
  gen_event:notify(?MODULE, Event).

add_handler(Module) ->
  add_handler(Module, []).

add_handler(Module, Args) ->
  gen_event:add_handler(?MODULE, Module, Args).
