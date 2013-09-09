-module(erldns).

-export([start/0]).

start() ->
  inets:start(),
  crypto:start(),
  ssl:start(),
  lager:start(),
  folsom:start(),
  application:start(ranch),
  application:start(cowboy),
  application:start(erldns).
