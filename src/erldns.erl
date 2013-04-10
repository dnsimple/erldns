-module(erldns).

-export([start/0]).

start() ->
  inets:start(),
  crypto:start(),
  ssl:start(),
  lager:start(),
  application:start(erldns).
