-module(erldns_edns).

-include("dns_records.hrl").

-export([handle/1]).

handle(Message) ->
  handle_opts(Message, Message#dns_message.additional).
  
handle_opts(Message, []) ->
  Message;
handle_opts(Message, [RR|Rest]) when is_record(RR, dns_optrr) ->
  lager:debug("~p:handle_opts(~p, [~p|Rest]) when dns_optrr", [?MODULE, Message, RR]),
  NewMessage = case RR#dns_optrr.dnssec of
    true -> erldns_dnssec:handle(Message);
    false -> Message
  end,
  handle_opts(NewMessage, Rest);
handle_opts(Message, [RR|Rest]) ->
  lager:debug("~p:handle_opts(~p, [~p|Rest])", [?MODULE, Message, RR]),
  handle_opts(Message, Rest).
