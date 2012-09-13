-module(erldns_dnssec).

-include("dns_records.hrl").

-export([handle/1]).

handle(Message) ->
  lager:info("Client wants DNSSEC"),
  Message.
