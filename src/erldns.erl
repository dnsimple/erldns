-module(erldns).

-export([start/0]).

start() ->
  lager:start(),
  application:start(folsom),
  application:start(mysql),
  application:start(erldns).
