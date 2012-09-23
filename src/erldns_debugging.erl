-module(erldns_debugging).

-export([start/0]).

start() ->
  timer:start(),
  spawn(fun() -> loop() end).

loop() ->
  loop(1).

loop(IterationNumber) ->
  lager:info("Iteration ~p (processes: ~p)", [IterationNumber, length(erlang:processes())]),
  timer:sleep(10000),
  loop(IterationNumber + 1).
