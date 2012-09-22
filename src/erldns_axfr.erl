-module(erldns_axfr).

-include("dns_records.hrl").

-export([is_enabled/2, optionally_append_soa/1]).

is_enabled(Host, Metadata) ->
  lager:debug("Checking AXFR for ~p", [Host]),
  lager:debug("Metadata: ~p", [Metadata]),

  MatchingMetadata = lists:filter(
      fun(MetadataRow) ->
          [_Id, _DomainId, Kind, Content] = MetadataRow,
          {ok, AllowedAddress} = inet_parse:address(binary_to_list(Content)),
          lager:debug("Checking ~p ~p", [Kind, AllowedAddress]),
          AllowedAddress =:= Host andalso Kind =:= <<"axfr">>
      end, Metadata),
  lager:debug("Matching metadata: ~p", [MatchingMetadata]),
  length(MatchingMetadata) > 0.

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
