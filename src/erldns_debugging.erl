-module(erldns_debugging).

-export([start/0]).

-define(MIN_PROCESS_COUNT, 500).

start() ->
  timer:start(),
  spawn_link(fun() -> loop() end).

loop() ->
  loop(1).

loop(IterationNumber) ->
  lager:info("Iteration ~p (processes: ~p)", [IterationNumber, length(erlang:processes())]),
  case length(erlang:processes()) of
    N when N > ?MIN_PROCESS_COUNT -> lager:info("~p", [lists:map(fun erlang:process_info/1, erlang:processes())]);
    _ -> ok
  end,
  timer:sleep(10000),
  loop(IterationNumber + 1).
