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

-export([include_nsec/5]).

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
  %lager:debug("include_nsec for ~p, ~p (CNAME chain: ~p)", [Qname, dns:type_name(Qtype), CnameChain]),

  AuthorityRecords =  lists:filter(empty_name_predicate(), Message#dns_message.authority),
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
      MessageWithNSEC = F(Message, Records, Qname, Qtype, Zone),
      sign_nsec_records(MessageWithNSEC, Zone)
  end.

nsec_function_set() ->
  lists:map(fun(Rule) -> {nsec_test(Rule), nsec_action(Rule)} end, [no_data, name_error, wildcard_answer, wildcard_no_data]).

empty_name_predicate() ->
  fun(R) ->
      R#dns_rr.name =/= <<"">>
  end.

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
    answers = Message#dns_message.answers ++ lists:map(fun(R) -> erldns_dnssec:sign_rrset(Message, Zone, R) end, lists:filter(erldns_records:match_type(?DNS_TYPE_NSEC), Message#dns_message.answers)),
    authority = Message#dns_message.authority ++ lists:map(fun(R) -> erldns_dnssec:sign_rrset(Message, Zone, R) end, lists:filter(erldns_records:match_type(?DNS_TYPE_NSEC), Message#dns_message.authority)),
    additional = Message#dns_message.additional ++ lists:map(fun(R) -> erldns_dnssec:sign_rrset(Message, Zone, R) end, Additional)
   }.


% @doc Determine if the RRSet matches the given NSEC rule.
-spec nsec_test(no_data|name_error|wildcard_answer|wildcard_no_data) -> fun(([dns:rr()], dns:dname(), dns:type(), [dns:rr()]) -> boolean()).
nsec_test(no_data) ->
  fun(RRSet, Qname, Qtype, _CnameChain) ->
      % exact match by name, but not type
      lists:any(
        fun(RR) ->
            case Qtype of
              ?DNS_TYPE_ANY -> false;
              _ -> (RR#dns_rr.name =:= Qname) and (RR#dns_rr.type =/= Qtype)
            end
        end, RRSet)
  end;
nsec_test(name_error) ->
  fun(RRSet, Qname, _Qtype, _CnameChain) ->
      % no match by name, including wildcard expansion
      lists:any(
        fun(RR) ->
            (erldns_records:wildcard_substitution(RR#dns_rr.name, Qname) =/= Qname)
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
          lager:debug("Calling add_nsec for RRSet ~p", [RRSet]),
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
          lager:debug("Calling add_nsec for RRSet ~p", [RRSet]),
          ZoneRecords = Zone#zone.records ++ erldns_dnssec:dnskey_rrset(Zone),
          add_nsec(Action, Message, Zone, ZoneRecords, Qname, RRSet)
      end
  end;
nsec_action(wildcard_answer) ->
  % no exact match by name, but match name and type with wildcard expansion
  fun(Message, RRSet, Qname, _Qtype, Zone) ->
      lager:debug("NSEC Wildcard Answer"),
      case RRSet of
        [] ->
          Message;
        _ ->
          ZoneRecords = Zone#zone.records ++ erldns_dnssec:dnskey_rrset(Zone),
          NSEC = [lists:last(lists:takewhile(fun(R) -> R#dns_rr.name < Qname end, dnssec:gen_nsec(ZoneRecords)))],
          Message#dns_message{authority = Message#dns_message.authority ++ NSEC}
      end
  end;
nsec_action(wildcard_no_data) ->
  fun(Message, RRSet, Qname, _Qtype, Zone) ->
      lager:debug("NSEC Wildcard No Data"),
      case RRSet of
        [] ->
          Message;
        _ ->
          lager:debug("Calling add_nsec for RRSet ~p", [RRSet]),
          ZoneRecords = Zone#zone.records ++ erldns_dnssec:dnskey_rrset(Zone),
          add_nsec(no_data, Message, Zone, ZoneRecords, Qname, RRSet)
      end
  end.

add_nsec(_, Message, _Zone, _ZoneRecords, _Qname, []) -> Message;

add_nsec(Action = no_data, Message, Zone, ZoneRecords, Qname, [_RR|Rest]) ->
  %lager:debug("add_nsec no data case for ~p", [RR#dns_rr.name]),
  AllNSEC = dnssec:gen_nsec(ZoneRecords),
  NSEC = lists:filter(erldns_records:match_name(Zone#zone.name), AllNSEC),
  MessageWithNSEC = Message#dns_message{authority = Message#dns_message.authority ++ NSEC},
  add_nsec(Action, MessageWithNSEC, Zone, ZoneRecords, Qname, Rest);

add_nsec(Action = name_error, Message, Zone, ZoneRecords, Qname, [_RR|Rest]) ->
  %lager:debug("add_nsec name error case for ~p", [RR#dns_rr.name]),
  AllNSEC = dnssec:gen_nsec(ZoneRecords),
  NSEC1 = lists:filter(erldns_records:match_name(Zone#zone.name), AllNSEC),
  NSEC2 = case lists:takewhile(fun(R) -> R#dns_rr.name < Qname end, AllNSEC) of
            [] -> [];
            NSEC -> [lists:last(NSEC)]
          end,

  NSECSet = case NSEC1 =:= NSEC2 of
              true -> NSEC1;
              false -> NSEC1 ++ NSEC2
            end,

  MessageWithNSEC = Message#dns_message{authority = Message#dns_message.authority ++ NSECSet},
  add_nsec(Action, MessageWithNSEC, Zone, ZoneRecords, Qname, Rest).


-ifdef(TEST).

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
   ?_assert(F([#dns_rr{name = <<"*.b1.example.com">>, type = Qtype}], Qname, Qtype, CnameChain))
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
