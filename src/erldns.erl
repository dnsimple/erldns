-module(erldns).

-export([start/0]).

start() ->
  application:start(mysql),
  application:start(erldns).
