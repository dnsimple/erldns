%% Copyright (c) 2012-2018, DNSimple Corporation
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

%% @doc Resolve a DNS query.
-module(erldns_resolver).

-include_lib("dns/include/dns.hrl").
-include("erldns.hrl").

-export([resolve/3]).

-callback get_records_by_name(dns:dname()) -> [dns:rr()].

%% @doc Resolve the questions in the message.
-spec resolve(Message :: dns:message(), AuthorityRecords :: [dns:rr()], Host :: dns:ip()) -> dns:message().
resolve(Message, AuthorityRecords, Host) ->
  resolve(Message, AuthorityRecords, Host, Message#dns_message.questions).


%% There were no questions in the message so just return it.
-spec resolve(dns:message(), [dns:rr()], dns:ip(), dns:questions() | dns:query()) -> dns:message().
resolve(Message, _AuthorityRecords, _Host, []) -> Message;
%% There is one question in the message; resolve it.
resolve(Message, AuthorityRecords, Host, [Question]) -> resolve(Message, AuthorityRecords, Host, Question);
%% Resolve the first question. Additional questions will be thrown away for now.
resolve(Message, AuthorityRecords, Host, [Question|_]) -> resolve(Message, AuthorityRecords, Host, Question);

%% Start the resolution process on the given question.
%% Step 1: Set the RA bit to false as we do not handle recursive queries.
%%
%% Refuse all RRSIG requests.
resolve(Message, AuthorityRecords, Host, Question) when is_record(Question, dns_query) ->
  case Question#dns_query.type of
    ?DNS_TYPE_RRSIG ->
      Message#dns_message{ra = false, ad = false, cd = false, rc = ?DNS_RCODE_REFUSED};
    Qtype ->
      check_dnssec(Message, Host, Question),
      resolve(Message#dns_message{ra = false, ad = false, cd = false}, AuthorityRecords, Question#dns_query.name, Qtype, Host)
  end.

%% With the extracted Qname and Qtype in hand, find the nearest zone
%% Step 2: Search the available zones for the zone which is the nearest ancestor to QNAME
%%
%% If the request required DNSSEC, apply the DNSSEC records
-spec resolve(dns:message(), [dns:rr()], dns:dname(), dns:type(), dns:ip()) -> dns:message().
resolve(Message, AuthorityRecords, Qname, Qtype, Host) ->
  Zone = erldns_zone_cache:find_zone(Qname, lists:last(AuthorityRecords)), % Zone lookup
  Records = resolve(Message, Qname, Qtype, Zone, Host, _CnameChain = []),
  sort_answers(erldns_dnssec:handle(additional_processing(erldns_records:rewrite_soa_ttl(Records), Host, Zone), Zone, Qname, Qtype)).

sort_answers(Message) ->
  Message#dns_message{answers = lists:usort(Message#dns_message.answers)}.

%% No SOA was found for the Qname so we return the root hints
%% Note: it seems odd that we are indicating we are authoritative here.
resolve(Message, _Qname, _Qtype, {error, not_authoritative}, _Host, _CnameChain) ->
  case erldns_config:use_root_hints() of
    true ->
      {Authority, Additional} = erldns_records:root_hints(),
      Message#dns_message{aa = true, rc = ?DNS_RCODE_NOERROR, authority = Authority, additional = Message#dns_message.additional ++ Additional};
    _ ->
      Message#dns_message{aa = true, rc = ?DNS_RCODE_NOERROR}
  end;

%% An SOA was found, thus we are authoritative and have the zone.
%% Step 3: Match records
resolve(Message, Qname, Qtype, Zone, Host, CnameChain) ->
  resolve(Message, Qname, Qtype, get_records_by_name(Zone, Qname), Host, CnameChain, Zone).

%% There were no exact matches on name, so move to the best-match resolution.
resolve(Message, Qname, Qtype, _MatchedRecords = [], Host, CnameChain, Zone) ->
  best_match_resolution(Message, Qname, Qtype, Host, CnameChain, best_match(Qname, Zone), Zone);

%% There was at least one exact match on name.
resolve(Message, Qname, Qtype, MatchedRecords, Host, CnameChain, Zone) ->
  exact_match_resolution(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone).



%% Determine if there is a CNAME anywhere in the records with the given Qname.
exact_match_resolution(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone) ->
  CnameRecords = lists:filter(erldns_records:match_type(?DNS_TYPE_CNAME), MatchedRecords), % Query record set for CNAME type
  exact_match_resolution(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone, CnameRecords).

%% No CNAME records found in the records with the Qname
exact_match_resolution(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone, _CnameRecords = []) ->
  resolve_exact_match(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone);

%% CNAME records found in the records for the Qname
exact_match_resolution(Message, _Qname, Qtype, Host, CnameChain, MatchedRecords, Zone, CnameRecords) ->
  resolve_exact_match_with_cname(Message, Qtype, Host, CnameChain, MatchedRecords, Zone, CnameRecords).




%% There were no CNAMEs found in the exact name matches, so now we grab the authority
%% records and find any type matches on QTYPE and continue on.
resolve_exact_match(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone) ->
  AuthorityRecords = lists:filter(erldns_records:match_type(?DNS_TYPE_SOA), MatchedRecords), % Query matched records for SOA type
  TypeMatches = case Qtype of
                  ?DNS_TYPE_ANY ->
                    filter_records(MatchedRecords, erldns_handler:get_handlers());
                  _ ->
                    lists:filter(erldns_records:match_type(Qtype), MatchedRecords)
                end,
  case TypeMatches of
    [] ->
      %% Ask the custom handlers for their records.
      NewRecords = erldns_dnssec:maybe_sign_rrset(Message, lists:flatten(lists:map(custom_lookup(Qname, Qtype, MatchedRecords), erldns_handler:get_handlers())), Zone),
      resolve_exact_match(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone, NewRecords, AuthorityRecords);
    _ ->
      resolve_exact_match(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone, TypeMatches, AuthorityRecords)
  end.

%% There were no matches for exact name and type, so now we are looking for NS records
%% in the exact name matches.
-spec(resolve_exact_match(
        Message :: dns:message(),
        Qname :: dns:dname(),
        Qtype :: 0..255,
        Host :: any(),
        CnameChain :: any(),
        MatchedRecords :: [dns:rr()],
        Zone :: #zone{},
        ExactTypeMatches :: dns:answers(),
        AuthorityRecords :: dns:authority()) ->
  dns:message()).
resolve_exact_match(Message, _Qname, Qtype, Host, CnameChain, MatchedRecords, Zone, _ExactTypeMatches = [], AuthorityRecords) ->
  ReferralRecords = lists:filter(erldns_records:match_type(?DNS_TYPE_NS), MatchedRecords), % Query matched records for NS type
  resolve_no_exact_type_match(Message, Qtype, Host, CnameChain, [], Zone, MatchedRecords, ReferralRecords, AuthorityRecords);

%% There were exact matches of name and type.
resolve_exact_match(Message, Qname, Qtype, Host, CnameChain, _MatchedRecords, Zone, ExactTypeMatches, AuthorityRecords) ->
  resolve_exact_type_match(Message, Qname, Qtype, Host, CnameChain, ExactTypeMatches, Zone, AuthorityRecords).



%% There was an exact type match for an NS query, however there is no SOA record for the zone.
resolve_exact_type_match(Message, _Qname, ?DNS_TYPE_NS, Host, CnameChain, MatchedRecords, Zone, []) ->
  Answer = lists:last(MatchedRecords),
  Name = Answer#dns_rr.name,
  % It isn't clear what the QTYPE should be on a delegated restart. I assume an A record.
  restart_delegated_query(Message, Name, ?DNS_TYPE_A, Host, CnameChain, Zone, erldns_zone_cache:in_zone(Name));

%% There was an exact type match for an NS query and an SOA record.
resolve_exact_type_match(Message, _Qname, ?DNS_TYPE_NS, _Host, _CnameChain, MatchedRecords, _Zone, _AuthorityRecords) ->
  Message#dns_message{aa = true, rc = ?DNS_RCODE_NOERROR, answers = Message#dns_message.answers ++ MatchedRecords};

%% There was an exact type match for something other than an NS record and we are authoritative because there is an SOA record.
resolve_exact_type_match(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone, _AuthorityRecords) ->
  % NOTE: this is a potential bug because it assumes the last record is the one to examine.
  Answer = lists:last(MatchedRecords),
  case erldns_zone_cache:get_delegations(Answer#dns_rr.name) of
    NSRecords = [] ->
      resolve_exact_type_match(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone, _AuthorityRecords, NSRecords);
    NSRecords ->
      NSRecord = lists:last(NSRecords),
      case erldns_zone_cache:get_authority(Qname) of
        {ok, [SoaRecord]} ->
          case SoaRecord#dns_rr.name =:= NSRecord#dns_rr.name of
            true ->
              Message#dns_message{aa = true, rc = ?DNS_RCODE_NOERROR, answers = Message#dns_message.answers ++ MatchedRecords};
            false ->
              resolve_exact_type_match(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone, _AuthorityRecords, NSRecords)
          end;
        {error, authority_not_found} ->
          resolve_exact_type_match(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone, _AuthorityRecords, NSRecords)
      end
  end.

%% We are authoritative and there were no NS records here.
resolve_exact_type_match(Message, _Qname, _Qtype, _Host, _CnameChain, MatchedRecords, _Zone, _AuthorityRecords, _NSRecords = []) ->
  Message#dns_message{aa = true, rc = ?DNS_RCODE_NOERROR, answers = Message#dns_message.answers ++ MatchedRecords};

%% We are authoritative and there are NS records here.
resolve_exact_type_match(Message, _Qname, Qtype, Host, CnameChain, MatchedRecords, Zone, _AuthorityRecords, NSRecords) ->
  % NOTE: there are potential bugs here because it assumes the last record is the one to examine
  Answer = lists:last(MatchedRecords),
  NSRecord = lists:last(NSRecords),
  Name = NSRecord#dns_rr.name,
  case Name =:= Answer#dns_rr.name of
    true -> % Handle NS recursion breakout
      Message#dns_message{aa = false, rc = ?DNS_RCODE_NOERROR, authority = Message#dns_message.authority ++ NSRecords};
    false ->
      % TODO: only restart delegation if the NS record is on a parent node
      % if it is a sibling then we should not restart
      case check_if_parent(Name, Answer#dns_rr.name) of
        true ->
          restart_delegated_query(Message, Name, Qtype, Host, CnameChain, Zone, erldns_zone_cache:in_zone(Name));
        false ->
          Message#dns_message{aa = true, rc = ?DNS_RCODE_NOERROR, answers = Message#dns_message.answers ++ MatchedRecords}
      end
  end.

%% Returns true if the first domain name is a parent of the second domain name.
check_if_parent(PossibleParentName, Name) ->
  case lists:subtract(dns:dname_to_labels(PossibleParentName), dns:dname_to_labels(Name)) of
    [] -> true;
    _ -> false
  end.


%% There were no exact type matches, but there were other name matches and there are NS records.
%% Since the Qtype is ANY we indicate we are authoritative and include the NS records.
-spec(resolve_no_exact_type_match(Message :: dns:message(), Qtype :: 0..255, Host :: any(), CnameChain :: any(), ExactTypeMatches :: dns:answers(), Zone :: #zone{}, MatchedRecords :: [dns:rr()], ReferralRecords :: [dns:rr()], AuthorityRecords :: dns:authority()) ->
  dns:message()).
resolve_no_exact_type_match(Message, _Qtype, _Host, _CnameChain, [], Zone, _MatchedRecords, [], _AuthorityRecords) ->
  Message#dns_message{aa = true, authority = Zone#zone.authority};
resolve_no_exact_type_match(Message, Qtype, _Host, _CnameChain, _ExactTypeMatches, _Zone, MatchedRecords, ReferralRecords, AuthorityRecords) ->
  resolve_exact_match_referral(Message, Qtype, MatchedRecords, ReferralRecords, AuthorityRecords).



% Given an exact name match where the Qtype is not found in the record set and we are not authoritative,
% add the NS records to the authority section of the message.
resolve_exact_match_referral(Message, _Qtype, _MatchedRecords, ReferralRecords, []) ->
  Message#dns_message{authority = Message#dns_message.authority ++ ReferralRecords};

% Given an exact name match and the type of ANY, return all of the matched records.
resolve_exact_match_referral(Message, ?DNS_TYPE_ANY, MatchedRecords, _ReferralRecords, _AuthorityRecords) ->
  Message#dns_message{aa = true, answers = MatchedRecords};
% Given an exact name match and the type NS, where the NS records are not found in record set
% return the NS records in the answers section of the message.
resolve_exact_match_referral(Message, ?DNS_TYPE_NS, _MatchedRecords, ReferralRecords, _AuthorityRecords) ->
  Message#dns_message{aa = true, answers = ReferralRecords};
% Given an exact name match and the type SOA, where the SOA record is not found in the records set,
% return the SOA records in the answers section of the message.
resolve_exact_match_referral(Message, ?DNS_TYPE_SOA, _MatchedRecords, _ReferralRecords, AuthorityRecords) ->
  Message#dns_message{aa = true, answers = AuthorityRecords};
% Given an exact name match where the Qtype is not found in the record set and is not ANY, SOA or NS,
% return the SOA records for the zone in the authority section of the message and set the RC to
% NOERROR.
resolve_exact_match_referral(Message, _, _MatchedRecords, _ReferralRecords, AuthorityRecords) ->
  Message#dns_message{aa = true, rc = ?DNS_RCODE_NOERROR, authority = AuthorityRecords}.



% There is a CNAME record and the request was for a CNAME record so append the CNAME records to
% the answers section.
resolve_exact_match_with_cname(Message, ?DNS_TYPE_CNAME, _Host, _CnameChain, _MatchedRecords, _Zone, CnameRecords) ->
  Message#dns_message{aa = true, answers = Message#dns_message.answers ++ CnameRecords};
% There is a CNAME record, however the Qtype is not CNAME, check for a CNAME loop before continuing.
resolve_exact_match_with_cname(Message, Qtype, Host, CnameChain, MatchedRecords, Zone, CnameRecords) ->
  resolve_exact_match_with_cname(Message, Qtype, Host, CnameChain, MatchedRecords, Zone, CnameRecords, lists:member(lists:last(CnameRecords), CnameChain)).

%% Indicates a CNAME loop. The response code is a SERVFAIL in this case.
resolve_exact_match_with_cname(Message, _Qtype, _Host, _CnameChain, _MatchedRecords, _Zone, _CnameRecords, true) ->
  Message#dns_message{aa = true, rc = ?DNS_RCODE_SERVFAIL};
% No CNAME loop, restart the query with the CNAME content.
resolve_exact_match_with_cname(Message, Qtype, Host, CnameChain, _MatchedRecords, Zone, CnameRecords, false) ->
  CnameRecord = lists:last(CnameRecords),
  Name = CnameRecord#dns_rr.data#dns_rrdata_cname.dname,
  restart_query(Message#dns_message{aa = true, answers = Message#dns_message.answers ++ CnameRecords}, Name, Qtype, Host, CnameChain ++ CnameRecords, Zone, erldns_zone_cache:in_zone(Name)).



% The CNAME is in a zone. If it is the same zone, then continue the chain, otherwise return the message
restart_query(Message, Name, Qtype, Host, CnameChain, Zone, true) ->
  Parent = check_if_parent(Zone#zone.name, Name),
  case Parent of
    true ->
      resolve(Message, Name, Qtype, Zone, Host, CnameChain);
    false ->
      Message
  end;
% The CNAME is not in a zone, do not restart the query, return the answer.
restart_query(Message, _Name, _Qtype, _Host, _CnameChain, _Zone, false) ->
  Message.

% Delegated, but in the same zone.
restart_delegated_query(Message, Name, Qtype, Host, CnameChain, Zone, true) ->
  resolve(Message, Name, Qtype, Zone, Host, CnameChain);
% Delegated to a different zone.
restart_delegated_query(Message, Name, Qtype, Host, CnameChain, Zone, false) ->
  resolve(Message, Name, Qtype, erldns_zone_cache:find_zone(Name, Zone#zone.authority), Host, CnameChain). % Zone lookup



% There was no exact match for the Qname, so we use the best matches that were
% returned by the best_match() function.
best_match_resolution(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone) ->
  ReferralRecords = lists:filter(erldns_records:match_type(?DNS_TYPE_NS), BestMatchRecords), % NS lookup
  best_match_resolution(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, ReferralRecords).

% There were no NS records in the best matches.
best_match_resolution(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, []) ->
  resolve_best_match(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone);
% There were NS records in the best matches, so this is a referral.
best_match_resolution(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, ReferralRecords) ->
  resolve_best_match_referral(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, ReferralRecords).


% There is no referral, so check to see if there is a wildcard.
resolve_best_match(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone) ->
  resolve_best_match(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, lists:any(erldns_records:match_wildcard(), BestMatchRecords)).

%% It's a wildcard match
resolve_best_match(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, true) ->
  CnameRecords = lists:filter(erldns_records:match_type(?DNS_TYPE_CNAME), lists:map(erldns_records:replace_name(Qname), BestMatchRecords)),
  resolve_best_match_with_wildcard(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, CnameRecords);
%% It is not a wildcard.
resolve_best_match(Message, Qname, _Qtype, _Host, _CnameChain, _BestMatchRecords, Zone, false) ->
  [Question|_] = Message#dns_message.questions,
  case Qname =:= Question#dns_query.name of
    true ->
      Message#dns_message{rc = ?DNS_RCODE_NXDOMAIN, authority = Zone#zone.authority, aa = true};
    false ->
      % This happens when we have a CNAME to an out-of-balliwick hostname and the query is for
      % something other than CNAME. Note that the response is still NOERROR here.
      %
      % In the dnstest suite, this is hit by cname_to_unauth_any (and others)
      case erldns_config:use_root_hints() of
        true ->
          {Authority, Additional} = erldns_records:root_hints(),
          Message#dns_message{authority = Authority, additional = Message#dns_message.additional ++ Additional};
        _ ->
          Message
      end
  end.


% It's a wildcard CNAME
resolve_best_match_with_wildcard(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone, []) ->
  TypeMatchedRecords = case Qtype of
                         ?DNS_TYPE_ANY ->
                           filter_records(MatchedRecords, erldns_handler:get_handlers());
                         _ ->
                           lists:filter(erldns_records:match_type(Qtype), MatchedRecords)
                       end,
  TypeMatches = lists:map(erldns_records:replace_name(Qname), TypeMatchedRecords),
  case TypeMatches of
    [] ->
      %% Ask the custom handlers for their records.
      NewRecords = erldns_dnssec:maybe_sign_rrset(Message, lists:map(erldns_records:replace_name(Qname), lists:flatten(lists:map(custom_lookup(Qname, Qtype, MatchedRecords), erldns_handler:get_handlers()))), Zone),
      resolve_best_match_with_wildcard(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone, [], NewRecords);
    _ ->
      resolve_best_match_with_wildcard(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone, [], TypeMatches)
  end;

% It is a wildcard CNAME
resolve_best_match_with_wildcard(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, CnameRecords) ->
  resolve_best_match_with_wildcard_cname(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, CnameRecords).

% It is not a CNAME and there were no exact type matches
resolve_best_match_with_wildcard(Message, _Qname, _Qtype, _Host, _CnameChain, _BestMatchRecords, Zone, [], []) ->
  Message#dns_message{aa = true, authority=Zone#zone.authority};

% It is not a CNAME and there were exact type matches
resolve_best_match_with_wildcard(Message, _Qname, _Qtype, _Host, _CnameChain, _BestMatchRecords, _Zone, [], TypeMatches) ->
  Message#dns_message{aa = true, answers = Message#dns_message.answers ++ TypeMatches}.




% It is a CNAME and the Qtype was CNAME
resolve_best_match_with_wildcard_cname(Message, _Qname, ?DNS_TYPE_CNAME, _Host, _CnameChain, _BestMatchRecords, _Zone, CnameRecords) ->
  Message#dns_message{aa = true, answers = Message#dns_message.answers ++ CnameRecords};

% It is a CNAME and the Qtype was not CNAME
resolve_best_match_with_wildcard_cname(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, CnameRecords) ->
  CnameRecord = lists:last(CnameRecords), % There should only be one CNAME. Multiple CNAMEs kill unicorns.
  resolve_best_match_with_wildcard_cname(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, CnameRecords, lists:member(CnameRecord, CnameChain)).

% Indicates CNAME loop
resolve_best_match_with_wildcard_cname(Message, _Qname, _Qtype, _Host, _CnameChain, _BestMatchRecords, _Zone, _CnameRecords, true) ->
  Message#dns_message{aa = true, rc = ?DNS_RCODE_SERVFAIL};

% We should follow the CNAME
resolve_best_match_with_wildcard_cname(Message, _Qname, Qtype, Host, CnameChain, _BestMatchRecords, Zone, CnameRecords, false) ->
  CnameRecord = lists:last(CnameRecords),
  Name = CnameRecord#dns_rr.data#dns_rrdata_cname.dname,
  restart_query(Message#dns_message{aa = true, answers = Message#dns_message.answers ++ CnameRecords}, Name, Qtype, Host, CnameChain ++ CnameRecords, Zone, erldns_zone_cache:in_zone(Name)).




% There are referral records
resolve_best_match_referral(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, ReferralRecords) ->
  resolve_best_match_referral(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, ReferralRecords, lists:filter(erldns_records:match_type(?DNS_TYPE_SOA), BestMatchRecords)). % Lookup SOA in best match records

% Indicate that we are not authoritative for the name as there were no
% SOA records in the best-match results. The name has thus been delegated
% to another authority.
resolve_best_match_referral(Message, _Qname, _Qtype, _Host, _CnameChain, _BestMatchRecords, _Zone, ReferralRecords, []) ->
  Message#dns_message{aa = false, authority = Message#dns_message.authority ++ ReferralRecords};

% We are authoritative for the name since there was an SOA record in
% the best match results.
resolve_best_match_referral(Message, _Qname, _Qtype, _Host, [], _BestMatchRecords, _Zone, _ReferralRecords, Authority) ->
  Message#dns_message{aa = true, rc = ?DNS_RCODE_NXDOMAIN, authority = Authority};

% We are authoritative and the Qtype is ANY so we just return the 
% original message.
resolve_best_match_referral(Message, _Qname, ?DNS_TYPE_ANY, _Host, _CnameChain, _BestMatchRecords, _Zone, _ReferralRecords, _Authority) ->
  Message;
resolve_best_match_referral(Message, _Qname, _Qtype, _Host, _CnameChain, _BestMatchRecords, _Zone, _ReferralRecords, Authority) ->
  Message#dns_message{authority = Authority}.




% Find the best match records for the given Qname in the
% given zone. This will attempt to walk through the
% domain hierarchy in the Qname looking for both exact and
% wildcard matches.
-spec best_match(dns:dname(), #zone{}) -> [dns:rr()].
best_match(Qname, Zone) -> best_match(Qname, dns:dname_to_labels(Qname), Zone).

best_match(_Qname, [], _Zone) -> [];
best_match(Qname, [_|Rest], Zone) ->
  WildcardName = dns:labels_to_dname([<<"*">>] ++ Rest),
  best_match(Qname, Rest, Zone,  get_records_by_name(Zone, WildcardName)).

best_match(_Qname, [], _Zone, []) -> [];
best_match(Qname, Labels, Zone, []) ->
  Name = dns:labels_to_dname(Labels),
  case get_records_by_name(Zone, Name) of
    [] -> best_match(Qname, Labels, Zone);
    Matches -> Matches
  end;
best_match(_Qname, _Labels, _Zone, WildcardMatches) -> WildcardMatches.



%% Function for executing custom lookups by registered handlers.
-spec custom_lookup(dns:dname(), dns:type(), [dns:rr()]) -> fun(({module(), [dns:type()]}) -> [dns:rr()]).
custom_lookup(Qname, Qtype, Records) ->
  fun({Module, Types}) ->
      case lists:member(Qtype, Types) of
        true -> Module:handle(Qname, Qtype, Records);
        false ->
          case Qtype =:= ?DNS_TYPE_ANY of
            true -> Module:handle(Qname, Qtype, Records);
            false -> []
          end
      end
  end.

% Function for filtering out custom records and replacing them with
% records which content from the custom handler.
filter_records(Records, []) -> Records;
filter_records(Records, [{Handler,_}|Rest]) ->
  filter_records(Handler:filter(Records), Rest).


%% See if additional processing is necessary.
additional_processing(Message, _Host, {error, _}) ->
  Message;
additional_processing(Message, Host, Zone) ->
  RequiresAdditionalProcessing = requires_additional_processing(Message#dns_message.answers ++ Message#dns_message.authority, []),
  additional_processing(Message, Host, Zone, lists:flatten(RequiresAdditionalProcessing)).
%% No records require additional processing.
additional_processing(Message, _Host, _Zone, []) ->
  Message;
%% There are records with names that require additional processing.
additional_processing(Message, Host, Zone, Names) ->
  RRs = lists:flatten(lists:map(fun(Name) -> get_records_by_name(Zone, Name) end, Names)),
  Records = lists:filter(erldns_records:match_types([?DNS_TYPE_A, ?DNS_TYPE_AAAA]), RRs),
  additional_processing(Message, Host, Zone, Names, Records).

%% No additional A records were found, so just return the message.
additional_processing(Message, _Host, _Zone, _Names, []) ->
  Message;
%% Additional A records were found, so we add them to the additional section.
additional_processing(Message, _Host, _Zone, _Names, Records) ->
  Message#dns_message{additional = Message#dns_message.additional ++ Records}.



%% Given a list of answers find the names that require additional processing.
requires_additional_processing([], RequiresAdditional) -> RequiresAdditional;
requires_additional_processing([Answer|Rest], RequiresAdditional) ->
  Names = case Answer#dns_rr.data of
            Data when is_record(Data, dns_rrdata_ns) -> [Data#dns_rrdata_ns.dname];
            Data when is_record(Data, dns_rrdata_mx) -> [Data#dns_rrdata_mx.exchange];
            _ -> []
          end,
  requires_additional_processing(Rest, RequiresAdditional ++ Names).

%% @doc Return true if DNSSEC is requested and enabled.
check_dnssec(Message, Host, Question) ->
  case proplists:get_bool(dnssec, erldns_edns:get_opts(Message)) of
    true ->
      erldns_events:notify({dnssec_request, Host, Question#dns_query.name});
    false ->
      ok
  end.

%% returns the record lookup delegation mdule for a zone.
get_delegate(#zone{name = Name}) ->
  case lists:keyfind(Name, 1, erldns_config:zone_delegates()) of
    false -> none;
    {Name, Delegate} -> {ok, Delegate}
  end.


get_records_by_name(Zone, Qname) ->
  case erldns_zone_cache:get_records_by_name(Qname) of
    [] ->
      get_delegate_records(Zone, Qname);
    Records ->
      Records
  end.

get_delegate_records(Zone, Qname) ->
  case get_delegate(Zone) of
    {ok, Delegate} ->
      Delegate:get_records_by_name(Qname);
    _ ->
      []
  end.
