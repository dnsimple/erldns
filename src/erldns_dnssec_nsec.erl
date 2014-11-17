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

-export([include_nsec/4]).

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
-spec include_nsec(dns:message()|[[dns:rr()]], dns:dname(), dns:type(), erldns:zone()) -> [[dns:rr()]].
include_nsec(Message, Qname, Qtype, Zone) when is_record(Message, dns_message) ->
  Message#dns_message{
    answers = Message#dns_message.answers + include_nsec([Message#dns_message.answers], Qname, Qtype, Zone),
    authority = Message#dns_message.authority + include_nsec([Message#dns_message.authority], Qname, Qtype, Zone),
    additional = Message#dns_message.additional + include_nsec([Message#dns_message.additional], Qname, Qtype, Zone)
   };
include_nsec(RRSets, Qname, Qtype, Zone) ->
  Functions = [
               {nsec_test(no_data), nsec_action(no_data)},
               {nsec_test(name_error), nsec_action(name_error)},
               {nsec_test(wildcard_answer), nsec_action(wildcard_answer)},
               {nsec_test(wildcard_no_data), nsec_action(wildcard_no_data)}
              ],
  lists:flatten(
    lists:map(fun({TestFunction, ActionFunction}) ->
                  lists:map(fun(RRSet) ->
                                case TestFunction(RRSet, Qname, Qtype) of
                                  true -> ActionFunction(RRSet, Qname, Qtype, Zone);
                                  false -> []
                                end
                            end, RRSets)
              end, Functions)).

-ifdef(TEST).
include_nsec_test_() ->
  Zone = #zone{},
  Qname = <<"a.a1.example.com">>,
  Qtype = ?DNS_TYPE_A,
  [
    ?_assertEqual([], include_nsec([[]], Qname, Qtype, Zone)),
    ?_assertEqual([], include_nsec([[#dns_rr{name = Qname, type = Qtype}]], Qname, Qtype, Zone))
  ].
-endif.


% @doc Determine if the RRSet matches the given NSEC rule.
-spec nsec_test(no_data|name_error|wildcard_answer|wildcard_no_data) -> boolean().
nsec_test(no_data) ->
  fun(RRSet, Qname, Qtype) ->
      % exact match by name, but not type
      lists:any(
        fun(RR) ->
            (RR#dns_rr.name =:= Qname) and (RR#dns_rr.type =/= Qtype)
        end, RRSet) 
  end;
nsec_test(name_error) ->
  fun(RRSet, Qname, _Qtype) ->
      % no match by name, including wildcard expansion
      lists:any(
        fun(RR) ->
            (erldns_records:wildcard_substitution(RR#dns_rr.name, Qname) =/= Qname)
        end, RRSet)
  end;
nsec_test(wildcard_answer) ->
  fun(RRSet, Qname, Qtype) ->
      % no exact match by name, but match name and type with wildcard expansion
      lists:any(
        fun(RR) ->
            (RR#dns_rr.name =/= Qname) and ((erldns_records:wildcard_substitution(RR#dns_rr.name, Qname) =:= Qname) and (RR#dns_rr.type =:= Qtype))
        end, RRSet)
  end;
nsec_test(wildcard_no_data) ->
  fun(RRSet, Qname, Qtype) ->
      % no exact match by name, exact match by name with wildcard, but not type
      lists:any(fun(RR) ->
                    (RR#dns_rr.name =/= Qname) and ((erldns_records:wildcard_substitution(RR#dns_rr.name, Qname) =:= Qname) and (RR#dns_rr.type =/= Qtype))
                end, RRSet)
  end.

-ifdef(TEST).
nsec_test_no_data_test_() ->
  Qname = <<"example.com">>,
  Qtype = ?DNS_TYPE_A,
  F = nsec_test(no_data),
  [
   ?_assertNot(F([], Qname, Qtype)),
   ?_assertNot(F([#dns_rr{name = Qname, type = Qtype}], Qname, Qtype)),
   ?_assert(F([#dns_rr{name = Qname, type = ?DNS_TYPE_NS}], Qname, Qtype)),
   ?_assert(F([#dns_rr{name = Qname, type = Qtype}, #dns_rr{name = Qname, type = ?DNS_TYPE_NS}], Qname, Qtype))
  ].

nsec_test_name_error_test_() ->
  Qname = <<"a.a1.example.com">>,
  Qtype = ?DNS_TYPE_A,
  F = nsec_test(name_error),
  [
   ?_assertNot(F([], Qname, Qtype)),
   ?_assertNot(F([#dns_rr{name = Qname, type = Qtype}], Qname, Qtype)),
   ?_assertNot(F([#dns_rr{name = Qname, type = ?DNS_TYPE_NS}], Qname, Qtype)),
   ?_assertNot(F([#dns_rr{name = <<"*.a1.example.com">>, type = Qtype}], Qname, Qtype)),
   ?_assert(F([#dns_rr{name = <<"*.b1.example.com">>, type = Qtype}], Qname, Qtype))
  ].

nsec_test_wildcard_answer_test_() ->
  % no exact match by name, but match name and type with wildcard expansion
  Qname = <<"a.a1.example.com">>,
  Qtype = ?DNS_TYPE_A,
  F = nsec_test(wildcard_answer),
  [
    ?_assertNot(F([], Qname, Qtype)),
    ?_assertNot(F([#dns_rr{name = Qname, type = Qtype}], Qname, Qtype)),
    ?_assertNot(F([#dns_rr{name = Qname, type = ?DNS_TYPE_NS}], Qname, Qtype)),
    ?_assert(F([#dns_rr{name = <<"*.a1.example.com">>, type = Qtype}], Qname, Qtype)),
    ?_assertNot(F([#dns_rr{name = <<"*.a1.example.com">>, type = ?DNS_TYPE_NS}], Qname, Qtype)),
    ?_assertNot(F([#dns_rr{name = <<"*.b1.example.com">>, type = Qtype}], Qname, Qtype))
  ].

nsec_test_wildcard_no_data_test_() ->
  % no exact match by name, exact match by name with wildcard, but not type
  Qname = <<"a.a1.example.com">>,
  Qtype = ?DNS_TYPE_A,
  F = nsec_test(wildcard_no_data),
  [
   ?_assertNot(F([], Qname, Qtype)),
   ?_assertNot(F([#dns_rr{name = Qname, type = Qtype}], Qname, Qtype)),
   ?_assertNot(F([#dns_rr{name = Qname, type = ?DNS_TYPE_NS}], Qname, Qtype)),
   ?_assertNot(F([#dns_rr{name = <<"*.a1.example.com">>, type = Qtype}], Qname, Qtype)),
   ?_assert(F([#dns_rr{name = <<"*.a1.example.com">>, type = ?DNS_TYPE_NS}], Qname, Qtype)),
   ?_assertNot(F([#dns_rr{name = <<"*.b1.example.com">>, type = Qtype}], Qname, Qtype))
  ].
-endif.

% @doc Given a particular case where NSEC is required, return the NSEC RR.
-spec nsec_action(no_data|name_error|wildcard_answer|wildcard_no_data) -> [dns:rr()].
nsec_action(no_data) ->
  % exact match by name, but not type
  fun(RRSet, _Qname, _Qtype, Zone) ->
      case RRSet of
        [] -> [];
        _ ->
          dnssec:gen_nsec(Zone#zone.records)
      end
  end;
nsec_action(name_error) ->
  fun(_RRSet, _Qname, _Qtype, _Zone) ->
      lager:debug("NSEC Name Error"),
      []
  end;
nsec_action(wildcard_answer) ->
  fun(_RRSet, _Qname, _Qtype, _Zone) ->
      lager:debug("NSEC Wildcard Answer"),
      []
  end;
nsec_action(wildcard_no_data) ->
  fun(_RRSet, _Qname, _Qtype, _Zone) ->
      lager:debug("NSEC Wildcard No Data"),
      []
  end.

-ifdef(TEST).
nsec_action_no_data_test_() ->
  % exact match by name, but not type
  Zone = #zone{records = [#dns_rr{name = <<"example.com">>, type = ?DNS_TYPE_SOA, data = #dns_rrdata_soa{minimum = 3600}}]},

  Qname = <<"example.com">>,
  Qtype = ?DNS_TYPE_A,
  F = nsec_action(no_data),

  RR = [#dns_rr{name = Qname, type = ?DNS_TYPE_NS}],
  [
    ?_assertEqual([], F([], Qname, Qtype, Zone)),

    fun() ->
        Actual = F(RR, Qname, Qtype, Zone),
        ?assertMatch([#dns_rr{name = Qname, type = ?DNS_TYPE_NSEC, ttl = 3600}], Actual),
        ?assertMatch([#dns_rr{data = #dns_rrdata_nsec{next_dname = <<"example.com">>}}], Actual),
        ?assertMatch([#dns_rr{data = #dns_rrdata_nsec{types = [?DNS_TYPE_SOA, ?DNS_TYPE_NSEC, ?DNS_TYPE_RRSIG]}}], Actual)
    end,

    fun() ->
      Zone1 = Zone#zone{records = Zone#zone.records ++ [#dns_rr{name = <<"example.com">>, type = ?DNS_TYPE_A}]},
      Actual = F(RR, Qname, Qtype, Zone1),
      ?assertMatch([#dns_rr{name = Qname, type = ?DNS_TYPE_NSEC, ttl = 3600}], Actual),
      ?assertMatch([#dns_rr{data = #dns_rrdata_nsec{next_dname = <<"example.com">>}}], Actual),
      ?assertMatch([#dns_rr{data = #dns_rrdata_nsec{types = [?DNS_TYPE_A, ?DNS_TYPE_SOA, ?DNS_TYPE_NSEC, ?DNS_TYPE_RRSIG]}}], Actual)
    end

  ].
-endif.
