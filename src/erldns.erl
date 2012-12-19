-module(erldns).

-export([start/0]).

start() ->
  lager:start(),
  folsom:start(),
  application:start(erldns),
  erldns_zone_cache:load_zones().
