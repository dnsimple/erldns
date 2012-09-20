-module(erldns_axfr).

-include("dns_records.hrl").

-define(AXFR_ENABLED, true).

-export([optionally_append_soa/1]).

%% If the message is an AXFR request then append the SOA record.
optionally_append_soa(Message) ->
  optionally_append_soa(Message, Message#dns_message.questions).

optionally_append_soa(Message, []) ->
  Message;
optionally_append_soa(Message, [Q|Rest]) ->
  case Q#dns_query.type of 
    ?DNS_TYPE_AXFR_NUMBER -> 
      append_soa(Message, Message#dns_message.answers);
    _ -> optionally_append_soa(Message, Rest)
  end.

append_soa(Message, []) ->
  Message;
append_soa(Message, Answers) ->
  [Answer|Rest] = Answers,
  append_soa(Message, Answer#dns_rr.type, Answer, Rest).

append_soa(Message, ?DNS_TYPE_SOA_NUMBER, Answer, _) ->
  Answers = lists:flatten(Message#dns_message.answers ++ [Answer]),
  Message#dns_message{anc = length(Answers), answers = Answers};
append_soa(Message, _, _, []) ->
  Message;
append_soa(Message, _, _, [Answer|Rest]) ->
  append_soa(Message, Answer#dns_rr.type, Answer, Rest).
