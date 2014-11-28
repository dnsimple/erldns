%% Copyright (c) 2012-2014, Aetrion LLC
%%
%% Permission to use, copy, modify, and/or distribute this software for any
%% purpose with or without fee is hereby granted, provided that the above
%% copyright notice and this permission notice appear in all copies.
%%
%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
%% WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
%% MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
%% ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
%% WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
%% ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
%% OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

%% @doc DNSSEC NSEC support methods.
-module(erldns_dnssec_nsec).

-export([include_nsec/5, sign_nsec_records/2, sort/1]).

-include("erldns.hrl").
-include_lib("dns/include/dns.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

% @doc Handle NSEC inclusion if required. There are four possible reasons to
% include NSEC data:
%
% No Data: The zone contains RRsets that exactly match <SNAME, SCLASS>
%      but does not contain any RRsets that exactly match <SNAME, SCLASS,
%      STYPE>.
%
%   Name Error: The zone does not contain any RRsets that match <SNAME,
%      SCLASS> either exactly or via wildcard name expansion.
%
%   Wildcard Answer: The zone does not contain any RRsets that exactly
%      match <SNAME, SCLASS> but does contain an RRset that matches
%      <SNAME, SCLASS, STYPE> via wildcard name expansion.
%
%   Wildcard No Data: The zone does not contain any RRsets that exactly
%      match <SNAME, SCLASS> and does contain one or more RRsets that
%      match <SNAME, SCLASS> via wildcard name expansion, but does not
%      contain any RRsets that match <SNAME, SCLASS, STYPE> via wildcard
%      name expansion.
%
%
% Note that the erldns:zone() that is passed in must have the full record set
% loaded.
-spec include_nsec(dns:message(), dns:dname(), dns:type(), erldns:zone(), [dns:dns_rr()]) -> dns:message().
include_nsec(Message, Qname, Qtype, Zone, CnameChain) when is_record(Message, dns_message) ->
  lager:debug("include_nsec for ~p, ~p", [Qname, dns:type_name(Qtype)]),

  AuthorityRecords =  lists:filter(erldns_records:empty_name_predicate(), Message#dns_message.authority),
  AllRecords = Message#dns_message.answers ++ AuthorityRecords,
  Records = lists:filter(erldns_records:not_match(erldns_records:match_type(?DNS_TYPE_RRSIG)), AllRecords),
  ActionFunctions = lists:map(
                      fun({TestFunction, ActionFunction}) ->
                          case TestFunction(lists:filter(erldns_records:not_match(erldns_records:match_optrr()), Records), Qname, Qtype, CnameChain) of
                            true -> ActionFunction;
                            false -> undefined
                          end
                      end, nsec_function_set()),
  ActionFunction = lists:filter(undefined_predicate(), ActionFunctions),

  case ActionFunction of
    [] -> Message;
    [F|_] ->
      dedupe(F(Message, Records, Qname, Qtype, Zone))
  end.

sort(Message) when is_record(Message, dns_message) ->
  Message#dns_message{authority = name_order(Message#dns_message.authority)}.

dedupe(Message) when is_record(Message, dns_message) ->
  Message#dns_message{authority = dedupe(Message#dns_message.authority)};
dedupe(Records) -> 
  dedupe(Records, _Found = [], _Duplicates = []).

dedupe([], Found, _Duplicates) ->
  Found;
dedupe([RR|Records], Found, Duplicates) ->
  case lists:any(fun(R) -> (R#dns_rr.name =:= RR#dns_rr.name) and (R#dns_rr.type =:= RR#dns_rr.type) and (R#dns_rr.data =:= RR#dns_rr.data) end, Found) of
    true -> dedupe(Records, Found, Duplicates ++ [RR]);
    false -> dedupe(Records, Found ++ [RR], Duplicates)
  end.


nsec_function_set() ->
  lists:map(fun(Rule) -> {nsec_test(Rule), nsec_action(Rule)} end, [no_data, name_error, wildcard_answer, wildcard_no_data]).

undefined_predicate() ->
  fun(F) ->
      case F of
        undefined -> false;
        _ -> true
      end
  end.


% @doc Sign the NSEC records in the DNS message.
-spec sign_nsec_records(dns:message(), erldns:zone()) -> dns:message().
sign_nsec_records(Message, Zone) ->
  Additional = lists:filter(erldns_records:match_type(?DNS_TYPE_NSEC), lists:filter(erldns_records:not_match(erldns_records:match_optrr()), Message#dns_message.additional)),
  Message#dns_message{
    answers = Message#dns_message.answers ++ lists:flatten(lists:map(fun(R) -> erldns_dnssec:sign_rrset(Message, Zone, R) end, lists:filter(erldns_records:match_type(?DNS_TYPE_NSEC), Message#dns_message.answers))),
    authority = Message#dns_message.authority ++ lists:flatten(lists:map(fun(R) -> erldns_dnssec:sign_rrset(Message, Zone, R) end, lists:filter(erldns_records:match_type(?DNS_TYPE_NSEC), Message#dns_message.authority))),
    additional = Message#dns_message.additional ++ lists:flatten(lists:map(fun(R) -> erldns_dnssec:sign_rrset(Message, Zone, R) end, Additional))
   }.


% @doc Determine if the RRSet matches the given NSEC rule.
-spec nsec_test(no_data|name_error|wildcard_answer|wildcard_no_data) -> fun(([dns:rr()], dns:dname(), dns:type(), [dns:rr()]) -> boolean()).
nsec_test(no_data) ->
  fun(RRSet, Qname, Qtype, _CnameChain) ->
      % exact match by name, but not type
      lists:any(
        fun(RR) ->
            case {Qtype, RR#dns_rr.type} of
              {_, ?DNS_TYPE_CNAME} -> false;
              {?DNS_TYPE_ANY, _} -> false;
              _ -> (RR#dns_rr.name =:= Qname) and (RR#dns_rr.type =/= Qtype)
            end
        end, RRSet)
  end;
nsec_test(name_error) ->
  fun(RRSet, Qname, Qtype, _CnameChain) ->
      % no match by name, including wildcard expansion
      lists:any(
        fun(RR) ->
            case {Qtype, RR#dns_rr.type} of
              {?DNS_TYPE_ANY, ?DNS_TYPE_CNAME} -> false;
              _ -> (erldns_records:wildcard_substitution(RR#dns_rr.name, Qname) =/= Qname)
            end
        end, RRSet)
  end;
nsec_test(wildcard_answer) ->
  fun(RRSet, Qname, Qtype, _CnameChain) ->
      % no exact match by name, but match name and type with wildcard expansion
      lists:any(
        fun(RR) ->
            (RR#dns_rr.name =/= Qname) and ((erldns_records:wildcard_substitution(RR#dns_rr.name, Qname) =:= Qname) and ((Qtype =:= ?DNS_TYPE_ANY) or (RR#dns_rr.type =:= Qtype)))
        end, RRSet)
  end;
nsec_test(wildcard_no_data) ->
  fun(RRSet, Qname, Qtype, _CnameChain) ->
      % no exact match by name, exact match by name with wildcard, but not type
      lists:any(
        fun(RR) ->
            case Qtype of
              ?DNS_TYPE_ANY -> false;
              _ -> (RR#dns_rr.name =/= Qname) and ((erldns_records:wildcard_substitution(RR#dns_rr.name, Qname) =:= Qname) and (RR#dns_rr.type =/= Qtype))
            end
        end, RRSet)
  end.



% @doc Given a particular case where NSEC is required, return the NSEC RR.
-spec nsec_action(no_data|name_error|wildcard_answer|wildcard_no_data) -> fun((dns:message(), [[dns:rr()]], dns:dname(), dns:type(), erldns:zone()) -> dns:message()).
nsec_action(Action = no_data) ->
  % exact match by name, but not type
  fun(Message, RRSet, Qname, _Qtype, Zone) ->
      lager:debug("NSEC No Data"),
      case RRSet of
        [] ->
          Message;
        _ ->
          %lager:debug("Calling add_nsec for RRSet ~p", [RRSet]),
          ZoneRecords = Zone#zone.records ++ erldns_dnssec:dnskey_rrset(Zone),
          add_nsec(Action, Message, Zone, ZoneRecords, Qname, RRSet)
      end
  end;
nsec_action(Action = name_error) ->
  % no match by name, including wildcard expansion
  fun(Message, RRSet, Qname, _Qtype, Zone) ->
      lager:debug("NSEC Name Error"),
      case RRSet of
        [] ->
          Message;
        _ ->
          %lager:debug("Calling add_nsec for RRSet ~p", [RRSet]),
          ZoneRecords = Zone#zone.records ++ erldns_dnssec:dnskey_rrset(Zone),
          add_nsec(Action, Message, Zone, ZoneRecords, Qname, RRSet)
      end
  end;
nsec_action(Action = wildcard_answer) ->
  % no exact match by name, but match name and type with wildcard expansion
  fun(Message, RRSet, Qname, _Qtype, Zone) ->
      lager:debug("NSEC Wildcard Answer"),
      case RRSet of
        [] ->
          Message;
        _ ->
          ZoneRecords = Zone#zone.records ++ erldns_dnssec:dnskey_rrset(Zone),
          add_nsec(Action, Message, Zone, ZoneRecords, Qname, RRSet)
      end
  end;
nsec_action(Action = wildcard_no_data) ->
  fun(Message, RRSet, Qname, _Qtype, Zone) ->
      lager:debug("NSEC Wildcard No Data"),
      case RRSet of
        [] ->
          Message;
        _ ->
          %lager:debug("Calling add_nsec for RRSet ~p", [RRSet]),
          ZoneRecords = Zone#zone.records ++ erldns_dnssec:dnskey_rrset(Zone),
          add_nsec(Action, Message, Zone, ZoneRecords, Qname, RRSet)
      end
  end.

add_nsec(_, Message, _Zone, _ZoneRecords, _Qname, []) -> Message;

add_nsec(Action = no_data, Message, Zone, ZoneRecords, Qname, [_RR|Rest]) ->
  % NSEC RR for <SNAME, SCLASS>

  NSEC = select_nsec(Zone, ZoneRecords, Zone#zone.name, false),
  lager:debug("NSEC: ~p", [NSEC]),
  Authority = Message#dns_message.authority ++ NSEC,
  MessageWithNSEC = Message#dns_message{authority = name_order(Authority)},
  add_nsec(Action, MessageWithNSEC, Zone, ZoneRecords, Qname, Rest);

add_nsec(Action = name_error, Message, Zone, ZoneRecords, Qname, [_RR|Rest]) ->
  % * An NSEC RR proving that there is no exact match for <SNAME, SCLASS>.
  % * An NSEC RR proving that the zone contains no RRsets that would match
  %   <SNAME, SCLASS> via wildcard name expansion.

  ENT = empty_non_terminal(Qname, ZoneRecords),
  lager:debug("ENT: ~p", [ENT]),

  NSEC = select_nsec(Zone, ZoneRecords, Qname, true),
  lager:debug("NSEC: ~p", [NSEC]),
  Authority = Message#dns_message.authority ++ NSEC,
  MessageWithNSEC = Message#dns_message{authority =  name_order(Authority)},
  add_nsec(Action, MessageWithNSEC, Zone, ZoneRecords, Qname, Rest);

add_nsec(Action = wildcard_answer, Message, Zone, ZoneRecords, Qname, [RR|Rest]) ->
  lager:debug("add_nsec ~p case for ~p", [Action, RR#dns_rr.name]),

  NSEC = select_nsec(Zone, ZoneRecords, Qname, false),
  Authority = Message#dns_message.authority ++ NSEC,
  MessageWithNSEC = Message#dns_message{authority =  name_order(Authority)},
  add_nsec(Action, MessageWithNSEC, Zone, ZoneRecords, Qname, Rest);

add_nsec(Action = wildcard_no_data, Message, Zone, ZoneRecords, Qname, [RR|Rest]) ->
  lager:debug("add_nsec ~p case for ~p", [Action, RR#dns_rr.name]),

  NSEC = select_nsec(Zone, ZoneRecords, Qname, true),
  Authority = Message#dns_message.authority ++ NSEC,
  MessageWithNSEC = Message#dns_message{authority =  name_order(Authority)},
  add_nsec(Action, MessageWithNSEC, Zone, ZoneRecords, Qname, Rest).


% @doc Select the NSEC records that are required from the zone to prove non-existence of the given
% qname.
-spec select_nsec(erldns:zone(), [dns:rr()], dns:dname(), boolean()) -> [dns:rr()].
select_nsec(Zone, ZoneRecords, Sname, _ExpandWildcard = true) ->
  select_nsec_with_wildcard(Zone, ZoneRecords, Sname, dnssec:gen_nsec(ZoneRecords));
select_nsec(Zone, ZoneRecords, Sname, _ExpandWildcard = false) ->
  select_nsec_without_wildcard(Zone, ZoneRecords, Sname, dnssec:gen_nsec(ZoneRecords)).

select_nsec_with_wildcard(Zone, _ZoneRecords, Sname, AllNSEC) ->
  NonWildcardNSEC = non_wildcard_nsec(Zone, Sname, AllNSEC),
  WildcardNSEC =  wildcard_nsec(Zone, Sname, AllNSEC),
  lager:debug("Non wildcard NSEC: ~p", [NonWildcardNSEC]),
  lager:debug("Wildcard NSEC: ~p", [WildcardNSEC]),
  dedupe(NonWildcardNSEC ++ WildcardNSEC).

select_nsec_without_wildcard(Zone, _ZoneRecords, Sname, AllNSEC) ->
  NonWildcardNSEC = non_wildcard_nsec(Zone, Sname, AllNSEC),
  dedupe(NonWildcardNSEC).

non_wildcard_nsec(Zone, Sname, AllNSEC) ->
  case lists:takewhile(fun(R) -> R#dns_rr.name < Sname end, AllNSEC) of
    [] -> lists:filter(erldns_records:match_name(Zone#zone.name), AllNSEC);
    NSEC -> [lists:last(NSEC)]
  end.

wildcard_nsec(Zone, _Qname, AllNSEC) ->
  Records = Zone#zone.records,
  %Records = erldns_resolver:best_match(Qname, Zone#zone.records),
  WildcardMatches = lists:filter(erldns_records:match_wildcard(), Records),
  %lager:debug("Wildcard matches: ~p", [WildcardMatches]),
  case WildcardMatches of
    [] -> lists:filter(erldns_records:match_name(Zone#zone.name), AllNSEC);
    _ -> lists:filter(erldns_records:match_name(Zone#zone.name), AllNSEC)
  end.

-spec empty_non_terminal(dns:dname(), [dns:rr()]) -> dns:dname().
empty_non_terminal(_Qname, []) -> undefined;
empty_non_terminal(Qname, [_RR|Rest]) ->
  empty_non_terminal(Qname, Rest).

%% Taken directly from dnssec.

name_order(RRs) when is_list(RRs) ->
    lists:sort(fun name_order/2, RRs).

name_order(X, X) -> true;
name_order(#dns_rr{name = X}, #dns_rr{name = X}) -> true;
name_order(#dns_rr{name = A}, #dns_rr{name = B}) ->
    LabelsA = lists:reverse(normalise_dname_to_labels(A)),
    LabelsB = lists:reverse(normalise_dname_to_labels(B)),
    name_order(LabelsA, LabelsB);
name_order([X|A], [X|B]) -> name_order(A,B);
name_order([], [_|_]) -> true;
name_order([_|_], []) -> false;
name_order([X|_], [Y|_]) -> X < Y.

normalise_dname(Name) -> dns:dname_to_lower(iolist_to_binary(Name)).

normalise_dname_to_labels(Name) -> dns:dname_to_labels(normalise_dname(Name)).

-ifdef(TEST).

select_nsec_test_() ->
  Zone = #zone{name = <<"example.com">>},
  SOAData = #dns_rrdata_soa{minimum = 600},
  Records = [
             #dns_rr{name = <<"example.com">>, type = ?DNS_TYPE_SOA, data = SOAData},
             #dns_rr{name = <<"foo.example.com">>, type = ?DNS_TYPE_A}
            ],
  [
   fun() ->
       Qname = <<"bar.example.com">>,
       Actual = select_nsec(Zone, Records, Qname, false),
       ?assertMatch([#dns_rr{type = ?DNS_TYPE_NSEC}], Actual),
       ?assertMatch([#dns_rr{data = #dns_rrdata_nsec{next_dname = <<"foo.example.com">>}}], Actual),
       ?assertMatch([#dns_rr{data = #dns_rrdata_nsec{types = [?DNS_TYPE_SOA, ?DNS_TYPE_NSEC, ?DNS_TYPE_RRSIG]}}], Actual)
   end,
   fun() ->
       Qname = <<"bar.example.com">>,
       Actual = select_nsec(Zone, Records, Qname, true),
       %RR = lists:last(Actual),
       %?debugVal(RR#dns_rr.data),
       ?assertMatch([#dns_rr{type = ?DNS_TYPE_NSEC}], Actual),
       ?assertMatch([#dns_rr{data = #dns_rrdata_nsec{next_dname = <<"foo.example.com">>}}], Actual),
       ?assertMatch([#dns_rr{data = #dns_rrdata_nsec{types = [?DNS_TYPE_SOA, ?DNS_TYPE_NSEC, ?DNS_TYPE_RRSIG]}}], Actual)
   end,
   fun() ->
       Qname = <<"zzz.example.com">>,
       Actual = select_nsec(Zone, Records, Qname, false),
       ?assertMatch([#dns_rr{type = ?DNS_TYPE_NSEC}], Actual),
       ?assertMatch([#dns_rr{data = #dns_rrdata_nsec{next_dname = <<"example.com">>}}], Actual)
   end,
   fun() ->
       Qname = <<"zzz.example.com">>,
       Actual = select_nsec(Zone, Records, Qname, true),
       ?assertMatch([#dns_rr{type = ?DNS_TYPE_NSEC}, #dns_rr{type = ?DNS_TYPE_NSEC}], Actual),
       ?assertMatch([#dns_rr{data = #dns_rrdata_nsec{next_dname = <<"example.com">>}}, #dns_rr{data = #dns_rrdata_nsec{next_dname = <<"foo.example.com">>}}], Actual)
   end
  ].

include_nsec_in_message_test_() ->
  Zone = #zone{},
  Qname = <<"a.a1.example.com">>,
  Qtype = ?DNS_TYPE_A,
  CnameChain = [],
  [
   fun() ->
       Message = #dns_message{answers = [], authority = [], additional = []},
       ?assertMatch(Message, include_nsec(Message, Qname, Qtype, Zone, CnameChain))
   end,
   fun() ->
       Message = #dns_message{answers = [#dns_rr{name = Qname, type = Qtype}], authority = [], additional = []},
       ?assertMatch(Message, include_nsec(Message, Qname, Qtype, Zone, CnameChain))
   end
  ].

dedupe_test_() ->
  RR = #dns_rr{name = <<"example.com">>, type = ?DNS_TYPE_A, data = #dns_rrdata_a{ip = {1, 2, 3, 4}}},
  RR2 = RR#dns_rr{data = #dns_rrdata_a{ip = {5,6,7,8}}},

  [
   ?_assertMatch(#dns_message{authority = []}, dedupe(#dns_message{authority = []})),
   ?_assertMatch(#dns_message{authority = [RR]}, dedupe(#dns_message{authority = [RR, RR]})),
   ?_assertMatch(#dns_message{authority = [RR, RR2]}, dedupe(#dns_message{authority = [RR, RR2]})),

   ?_assertEqual([], dedupe([])),
   ?_assertEqual([RR], dedupe([RR, RR])),
   ?_assertEqual([RR, RR2], dedupe([RR, RR2]))
  ].

sign_nsec_records_test_() ->
  Zone = #zone{},
  Message = #dns_message{answers = [], authority = [], additional = []},
  [
   ?_assertMatch(Message, sign_nsec_records(Message, Zone))
  ].


nsec_test_no_data_test_() ->
  Qname = <<"example.com">>,
  Qtype = ?DNS_TYPE_A,
  CnameChain = [],
  F = nsec_test(no_data),
  [
   ?_assertNot(F([], Qname, Qtype, CnameChain)),
   ?_assertNot(F([#dns_rr{name = Qname, type = Qtype}], Qname, Qtype, CnameChain)),
   ?_assertNot(F([#dns_rr{name = Qname, type = ?DNS_TYPE_A}], Qname, ?DNS_TYPE_ANY, CnameChain)),
   ?_assert(F([#dns_rr{name = Qname, type = ?DNS_TYPE_NS}], Qname, Qtype, CnameChain)),
   ?_assert(F([#dns_rr{name = Qname, type = Qtype}, #dns_rr{name = Qname, type = ?DNS_TYPE_NS}], Qname, Qtype, CnameChain))
  ].

nsec_test_name_error_test_() ->
  % no match by name, including wildcard expansion
  Qname = <<"a.a1.example.com">>,
  Qtype = ?DNS_TYPE_A,
  CnameChain = [],
  F = nsec_test(name_error),
  [
   ?_assertNot(F([], Qname, Qtype, CnameChain)),
   ?_assertNot(F([#dns_rr{name = Qname, type = Qtype}], Qname, Qtype, CnameChain)),
   ?_assertNot(F([#dns_rr{name = Qname, type = ?DNS_TYPE_NS}], Qname, Qtype, CnameChain)),
   ?_assertNot(F([#dns_rr{name = <<"*.a1.example.com">>, type = Qtype}], Qname, Qtype, CnameChain)),
   ?_assert(F([#dns_rr{name = <<"*.b1.example.com">>, type = Qtype}], Qname, Qtype, CnameChain)),
   ?_assert(F([#dns_rr{name = <<"a.b1.example.com">>, type = Qtype}], Qname, ?DNS_TYPE_ANY, CnameChain)),
   ?_assertNot(F([#dns_rr{name = <<"a.b1.example.com">>, type = ?DNS_TYPE_CNAME}], Qname, ?DNS_TYPE_ANY, CnameChain))
  ].

nsec_test_wildcard_answer_test_() ->
  % no exact match by name, but match name and type with wildcard expansion
  Qname = <<"a.a1.example.com">>,
  Qtype = ?DNS_TYPE_A,
  CnameChain = [],
  F = nsec_test(wildcard_answer),
  [
   ?_assertNot(F([], Qname, Qtype, CnameChain)),
   ?_assertNot(F([#dns_rr{name = Qname, type = Qtype}], Qname, Qtype, CnameChain)),
   ?_assertNot(F([#dns_rr{name = Qname, type = ?DNS_TYPE_NS}], Qname, Qtype, CnameChain)),
   ?_assert(F([#dns_rr{name = <<"*.a1.example.com">>, type = Qtype}], Qname, Qtype, CnameChain)),
   ?_assert(F([#dns_rr{name = <<"*.a1.example.com">>, type = Qtype}], Qname, ?DNS_TYPE_ANY, CnameChain)),
   ?_assertNot(F([#dns_rr{name = <<"*.a1.example.com">>, type = ?DNS_TYPE_NS}], Qname, Qtype, CnameChain)),
   ?_assertNot(F([#dns_rr{name = <<"*.b1.example.com">>, type = Qtype}], Qname, Qtype, CnameChain))
  ].

nsec_test_wildcard_no_data_test_() ->
  % no exact match by name, exact match by name with wildcard, but not type
  Qname = <<"a.a1.example.com">>,
  Qtype = ?DNS_TYPE_A,
  CnameChain = [],
  F = nsec_test(wildcard_no_data),
  [
   ?_assertNot(F([], Qname, Qtype, CnameChain)),
   ?_assertNot(F([#dns_rr{name = Qname, type = Qtype}], Qname, Qtype, CnameChain)),
   ?_assertNot(F([#dns_rr{name = Qname, type = ?DNS_TYPE_NS}], Qname, Qtype, CnameChain)),
   ?_assertNot(F([#dns_rr{name = <<"*.a1.example.com">>, type = Qtype}], Qname, Qtype, CnameChain)),
   ?_assertNot(F([#dns_rr{name = <<"*.a1.example.com">>, type = Qtype}], Qname, ?DNS_TYPE_ANY, CnameChain)),
   ?_assert(F([#dns_rr{name = <<"*.a1.example.com">>, type = ?DNS_TYPE_NS}], Qname, Qtype, CnameChain)),
   ?_assertNot(F([#dns_rr{name = <<"*.b1.example.com">>, type = Qtype}], Qname, Qtype, CnameChain))
  ].


nsec_action_no_data_test_() ->
  % exact match by name, but not type
  Message = #dns_message{},
  SoaRRSet = [#dns_rr{name = <<"example.com">>, type = ?DNS_TYPE_SOA, data = #dns_rrdata_soa{minimum = 3600}}],
  DnskeyRRSet = [
                 #dns_rr{name = <<"example.com">>, type = ?DNS_TYPE_DNSKEY, data = #dns_rrdata_dnskey{flags = 257}},
                 #dns_rr{name = <<"example.com">>, type = ?DNS_TYPE_DNSKEY, data = #dns_rrdata_dnskey{flags = 256}}
                ],
  Zone = #zone{name = <<"example.com">>, authority = SoaRRSet, records = SoaRRSet ++ DnskeyRRSet},
  Qname = <<"example.com">>,
  Qtype = ?DNS_TYPE_A,
  F = nsec_action(no_data),

  RR = [#dns_rr{name = Qname, type = ?DNS_TYPE_NS}],
  [
   ?_assertMatch(#dns_message{authority = []}, F(Message, [], Qname, Qtype, Zone)),

   fun() ->
       Actual = F(Message, RR, Qname, Qtype, Zone),
       ?assertMatch(#dns_message{authority = [#dns_rr{name = Qname, type = ?DNS_TYPE_NSEC, ttl = 3600}]}, Actual),
       ?assertMatch(#dns_message{authority = [#dns_rr{data = #dns_rrdata_nsec{next_dname = <<"example.com">>}}]}, Actual),
       ?assertMatch(#dns_message{authority = [#dns_rr{data = #dns_rrdata_nsec{types = [?DNS_TYPE_DNSKEY, ?DNS_TYPE_SOA, ?DNS_TYPE_NSEC, ?DNS_TYPE_RRSIG]}}]}, Actual)
   end,

   fun() ->
       Zone1 = Zone#zone{records = Zone#zone.records ++ [#dns_rr{name = <<"example.com">>, type = ?DNS_TYPE_A}]},
       Actual = F(Message, RR, Qname, Qtype, Zone1),
       ?assertMatch(#dns_message{authority = [#dns_rr{name = Qname, type = ?DNS_TYPE_NSEC, ttl = 3600}]}, Actual),
       ?assertMatch(#dns_message{authority = [#dns_rr{data = #dns_rrdata_nsec{next_dname = <<"example.com">>}}]}, Actual),
       ?assertMatch(#dns_message{authority = [#dns_rr{data = #dns_rrdata_nsec{types = [?DNS_TYPE_A, ?DNS_TYPE_DNSKEY, ?DNS_TYPE_SOA, ?DNS_TYPE_NSEC, ?DNS_TYPE_RRSIG]}}]}, Actual)
   end

  ].

nsec_action_name_error_test_() ->
  % no match by name, including wildcard expansion
  Message = #dns_message{},
  SoaRRSet = [#dns_rr{name = <<"example.com">>, type = ?DNS_TYPE_SOA, data = #dns_rrdata_soa{minimum = 3600}}],
  DnskeyRRSet = [
                 #dns_rr{name = <<"example.com">>, type = ?DNS_TYPE_DNSKEY, data = #dns_rrdata_dnskey{flags = 257}},
                 #dns_rr{name = <<"example.com">>, type = ?DNS_TYPE_DNSKEY, data = #dns_rrdata_dnskey{flags = 256}}
                ],
  Zone = #zone{name = <<"example.com">>, authority = SoaRRSet, records = SoaRRSet ++ DnskeyRRSet},
  Qname = <<"nxdomain.example.com">>,
  Qtype = ?DNS_TYPE_A,
  F = nsec_action(name_error),

  RR = [#dns_rr{name = Qname, type = ?DNS_TYPE_NS}],
  [
   ?_assertMatch(#dns_message{authority = []}, F(Message, [], Qname, Qtype, Zone)),

   fun() ->
       Actual = F(Message, RR, Qname, Qtype, Zone),
       ?assertMatch(#dns_message{authority = [#dns_rr{name = <<"example.com">>, type = ?DNS_TYPE_NSEC, ttl = 3600}]}, Actual),
       ?assertMatch(#dns_message{authority = [#dns_rr{data = #dns_rrdata_nsec{next_dname = <<"example.com">>}}]}, Actual)
   end,

   fun() ->
       Records = [#dns_rr{name = <<"alpha.example.com">>, type = ?DNS_TYPE_A}, #dns_rr{name = <<"outpost.example.com">>, type = ?DNS_TYPE_A}],
       Zone1 = Zone#zone{records = Zone#zone.records ++ Records},
       Actual = F(Message, RR, Qname, Qtype, Zone1),
       %?debugVal(Actual#dns_message.authority),
       ?assertMatch(#dns_message{authority = [#dns_rr{name = <<"example.com">>, type = ?DNS_TYPE_NSEC}, #dns_rr{name = <<"alpha.example.com">>, type = ?DNS_TYPE_NSEC}]}, Actual),
       ?assertMatch(#dns_message{authority = [#dns_rr{data = #dns_rrdata_nsec{next_dname = <<"alpha.example.com">>}}, #dns_rr{data = #dns_rrdata_nsec{next_dname = <<"outpost.example.com">>}}]}, Actual),
       ?assertMatch(#dns_message{authority = [#dns_rr{data = #dns_rrdata_nsec{types = [?DNS_TYPE_DNSKEY, ?DNS_TYPE_SOA, ?DNS_TYPE_NSEC, ?DNS_TYPE_RRSIG]}}, #dns_rr{data = #dns_rrdata_nsec{types = [?DNS_TYPE_A, ?DNS_TYPE_NSEC, ?DNS_TYPE_RRSIG]}}]}, Actual)
   end
  ].
-endif.
