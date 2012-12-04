-module(erldns_handler).

-include("dns.hrl").
-include("erldns.hrl").

-export([handle/2]).

% Internal API
-export([resolve/4, find_zone/1, build_named_index/1, requires_additional_processing/2, additional_processing/3, additional_processing/4, rewrite_soa_ttl/1]).

%% Handle the decoded message
handle({trailing_garbage, Message, _}, Host) ->
  handle(Message, Host);
handle(Message, Host) when is_record(Message, dns_message) ->
  case erldns_query_throttle:throttle(Message, Host) of
    {throttled, Host, ReqCount} ->
      lager:info("Throttled ANY query for ~p. (req count: ~p)", [Host, ReqCount]),
      Message#dns_message{rc = ?DNS_RCODE_REFUSED};
    _ ->
      lager:info("Questions: ~p", [Message#dns_message.questions]),
      NewMessage = handle_message(Message, Host),
      complete_response(erldns_axfr:optionally_append_soa(erldns_edns:handle(NewMessage)))
  end;
handle(BadMessage, Host) ->
  lager:error("Received a bad message: ~p from ~p", [BadMessage, Host]),
  BadMessage.

%% Handle the message by hitting the packet cache and either
%% using the cached packet or continuing with the lookup process.
handle_message(Message, Host) ->
  case erldns_packet_cache:get(Message#dns_message.questions) of
    {ok, CachedResponse} -> CachedResponse#dns_message{id=Message#dns_message.id};
    {error, _} -> handle_packet_cache_miss(Message, get_soas(Message), Host)
  end.

%% If the packet is not in the cache and we are not authoritative, then answer
%% immediately with the root delegation hints.
handle_packet_cache_miss(Message, [], _Host) ->
  {Authority, Additional} = erldns_records:root_hints(),
  Message#dns_message{aa = false, rc = ?DNS_RCODE_NOERROR, authority = Authority, additional = Additional};
%% The packet is not in the cache yet we are authoritative, so try to resolve
%% the request.
handle_packet_cache_miss(Message, AuthorityRecords, Host) ->
  handle_packet_cache_miss(Message#dns_message{ra = false}, AuthorityRecords, Host, Message#dns_message.aa).

handle_packet_cache_miss(Message, AuthorityRecords, Host, Authoritative) ->
  case application:get_env(erldns, catch_exceptions) of
    {ok, false} -> maybe_cache_packet(resolve(Message, AuthorityRecords, Host), Authoritative);
    _ ->
      try resolve(Message, AuthorityRecords, Host) of
        Response -> maybe_cache_packet(Response, Authoritative)
      catch
        Exception:Reason ->
          lager:error("Error answering request: ~p (~p)", [Exception, Reason]),
          Message#dns_message{aa = false, rc = ?DNS_RCODE_SERVFAIL}
      end
  end.

%% We are authoritative so cache the packet.
maybe_cache_packet(Message, true) ->
  erldns_packet_cache:put(Message#dns_message.questions, Message),
  Message;
%% We are not authoritative so just return the message.
maybe_cache_packet(Message, false) ->
  Message.

%% Resolve the first question inside the given message.
resolve(Message, AuthorityRecords, Host) -> resolve(Message, AuthorityRecords, Host, Message#dns_message.questions).

resolve(Message, _AuthorityRecords, _Host, []) -> Message;
resolve(Message, AuthorityRecords, Host, [Question]) -> erldns_metrics:measure(Question#dns_query.name, ?MODULE, resolve, [Message, AuthorityRecords, Host, Question]);
resolve(Message, AuthorityRecords, Host, [Question|_]) -> erldns_metrics:measure(Question#dns_query.name, ?MODULE, resolve, [Message, AuthorityRecords, Host, Question]);
resolve(Message, AuthorityRecords, Host, Question) when is_record(Question, dns_query) ->
  % Step 1: Set the RA bit to false
  resolve(Message#dns_message{ra = false}, AuthorityRecords, Question#dns_query.name, Question#dns_query.type, Host).

resolve(Message, AuthorityRecords, Qname, Qtype, Host) ->
  % Step 2: Search the available zones for the zone which is the nearest ancestor to QNAME
  lager:info("resolve with SOAs: ~p", [AuthorityRecords]),
  Zone = find_zone(Qname),
  Records = resolve(Message, Qname, Qtype, Zone#zone{authority=lists:last(AuthorityRecords)}, Host, []),
  RewrittenRecords = erldns_metrics:measure(none, ?MODULE, rewrite_soa_ttl, [Records]),
  erldns_metrics:measure(none, ?MODULE, additional_processing, [RewrittenRecords, Host, Zone]).

resolve(Message, Qname, Qtype, Zone, Host, CnameChain) ->
  lager:info("Zone has ~p records", [length(Zone#zone.records)]),
  % Step 3: Match records
  resolve(Message, Qname, Qtype, find_records_by_name(Qname, Zone), Host, CnameChain, Zone).

%% There were no exact matches on name, so move to the best-match resolution.
resolve(Message, Qname, Qtype, [], Host, CnameChain, Zone) ->
  best_match_resolution(Message, Qname, Qtype, Host, CnameChain, best_match(Qname, Zone), Zone);
%% There was at least one exact match on name.
resolve(Message, Qname, Qtype, MatchedRecords, Host, CnameChain, Zone) ->
  exact_match_resolution(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone).

%% Determine if there is a CNAME anywhere in the records with the given Qname.
exact_match_resolution(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone) ->
  exact_match_resolution(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone, lists:filter(match_type(?DNS_TYPE_CNAME), MatchedRecords)).
%% No CNAME records found in the records with the Qname
exact_match_resolution(Message, _Qname, Qtype, Host, CnameChain, MatchedRecords, Zone, []) ->
  resolve_exact_match(Message, Qtype, Host, CnameChain, MatchedRecords, Zone);
%% CNAME records found in the records for the Qname
exact_match_resolution(Message, _Qname, Qtype, Host, CnameChain, MatchedRecords, Zone, CnameRecords) ->
  resolve_exact_match_with_cname(Message, Qtype, Host, CnameChain, MatchedRecords, Zone, CnameRecords).

%% There were no CNAMEs found in the exact name matches, so now we grab the authority
%% records and find any type matches on QTYPE and continue on.
resolve_exact_match(Message, Qtype, Host, CnameChain, MatchedRecords, Zone) ->
  AuthorityRecords = lists:filter(match_type(?DNS_TYPE_SOA), MatchedRecords),
  TypeMatches = lists:filter(match_type(Qtype), MatchedRecords),
  resolve_exact_match(Message, Qtype, Host, CnameChain, MatchedRecords, Zone, TypeMatches, AuthorityRecords).

resolve_exact_match(Message, Qtype, Host, CnameChain, MatchedRecords, Zone, [], AuthorityRecords) ->
  ReferralRecords = lists:filter(match_type(?DNS_TYPE_NS), MatchedRecords),
  resolve_no_exact_type_match(Message, Qtype, Host, CnameChain, [], Zone, MatchedRecords, ReferralRecords, AuthorityRecords);
resolve_exact_match(Message, Qtype, Host, CnameChain, _MatchedRecords, Zone, ExactTypeMatches, AuthorityRecords) ->
  resolve_exact_type_match(Message, Qtype, Host, CnameChain, ExactTypeMatches, Zone, AuthorityRecords).

resolve_exact_type_match(Message, ?DNS_TYPE_NS, Host, CnameChain, MatchedRecords, Zone, []) ->
  Answer = lists:last(MatchedRecords),
  Name = Answer#dns_rr.name,
  lager:debug("Restarting query with delegated name ~p", [Name]),
  % It isn't clear what the QTYPE should be on a delegated restart. I assume an A record.
  case in_zone(Name, Zone) of
    true -> resolve(Message, Name, ?DNS_TYPE_A, Zone, Host, CnameChain);
    false -> resolve(Message, Name, ?DNS_TYPE_A, find_zone(Name), Host, CnameChain)
  end;
resolve_exact_type_match(Message, ?DNS_TYPE_NS, _Host, _CnameChain, MatchedRecords, _Zone, _AuthorityRecords) ->
  lager:debug("Authoritative for record, returning answers"),
  Message#dns_message{aa = true, rc = ?DNS_RCODE_NOERROR, answers = Message#dns_message.answers ++ MatchedRecords};
resolve_exact_type_match(Message, Qtype, Host, CnameChain, MatchedRecords, Zone, _AuthorityRecords) ->
  Answer = lists:last(MatchedRecords),
  NSRecords = delegation_records(Answer#dns_rr.name, Zone#zone.records),
  resolve_exact_type_match(Message, Qtype, Host, CnameChain, MatchedRecords, Zone, _AuthorityRecords, NSRecords).

resolve_exact_type_match(Message, _Qtype, _Host, _CnameChain, MatchedRecords, _Zone, _AuthorityRecords, []) ->
  lager:debug("Returning authoritative answer with ~p appended answers", [length(MatchedRecords)]),
  Message#dns_message{aa = true, rc = ?DNS_RCODE_NOERROR, answers = Message#dns_message.answers ++ MatchedRecords};
resolve_exact_type_match(Message, Qtype, Host, CnameChain, _MatchedRecords, Zone, _AuthorityRecords, NSRecords) ->
  NSRecord = lists:last(NSRecords),
  DelegatedName = NSRecord#dns_rr.name,
  lager:debug("Restarting query with delegated name ~p", [DelegatedName]),
  case in_zone(DelegatedName, Zone) of
    true -> resolve(Message, DelegatedName, Qtype, Zone, Host, CnameChain);
    false -> resolve(Message, DelegatedName, Qtype, find_zone(DelegatedName), Host, CnameChain)
  end.

resolve_no_exact_type_match(Message, ?DNS_TYPE_ANY, _Host, _CnameChain, _ExactTypeMatches, _Zone, [], [], AuthorityRecords) ->
  Message#dns_message{aa = true, authority = AuthorityRecords};
resolve_no_exact_type_match(Message, _Qtype, _Host, _CnameChain, [], Zone, _MatchedRecords, [], _AuthorityRecords) ->
  lager:info("resolve_no_exact_type_match"),
  Authority = lists:filter(match_type(?DNS_TYPE_SOA), Zone#zone.records),
  Message#dns_message{aa = true, authority = Authority};
resolve_no_exact_type_match(Message, _Qtype, _Host, _CnameChain, ExactTypeMatches, _Zone, _MatchedRecords, [], _AuthorityRecords) ->
  Message#dns_message{aa = true, answers = Message#dns_message.answers ++ ExactTypeMatches};
resolve_no_exact_type_match(Message, Qtype, _Host, _CnameChain, _ExactTypeMatches, _Zone, MatchedRecords, ReferralRecords, AuthorityRecords) ->
  resolve_exact_match_referral(Message, Qtype, MatchedRecords, ReferralRecords, AuthorityRecords).

resolve_exact_match_referral(Message, _Qtype, _MatchedRecords, ReferralRecords, []) ->
  Message#dns_message{authority = Message#dns_message.authority ++ ReferralRecords};
resolve_exact_match_referral(Message, ?DNS_TYPE_ANY, MatchedRecords, _ReferralRecords, _AuthorityRecords) ->
  Message#dns_message{aa = true, answers = MatchedRecords};
resolve_exact_match_referral(Message, ?DNS_TYPE_NS, _MatchedRecords, ReferralRecords, _AuthorityRecords) ->
  Message#dns_message{aa = true, answers = ReferralRecords};
resolve_exact_match_referral(Message, ?DNS_TYPE_SOA, _MatchedRecords, _ReferralRecords, AuthorityRecords) ->
  Message#dns_message{aa = true, answers = AuthorityRecords};
resolve_exact_match_referral(Message, _, _MatchedRecords, _ReferralRecords, AuthorityRecords) ->
  Message#dns_message{aa = true, rc = ?DNS_RCODE_NOERROR, authority = AuthorityRecords}.

% There is a CNAME record and the request was for a CNAME record, so just return the CNAME records.
resolve_exact_match_with_cname(Message, ?DNS_TYPE_CNAME, _Host, _CnameChain, _MatchedRecords, _Zone, CnameRecords) ->
  Message#dns_message{aa = true, answers = Message#dns_message.answers ++ CnameRecords};
% There is a CNAME record, however the type is not CNAME, check for a CNAME loop before continuing
resolve_exact_match_with_cname(Message, Qtype, Host, CnameChain, MatchedRecords, Zone, CnameRecords) ->
  resolve_exact_match_with_cname(Message, Qtype, Host, CnameChain, MatchedRecords, Zone, CnameRecords, lists:member(lists:last(CnameRecords), CnameChain)).

%% Indicates a CNAME loop
resolve_exact_match_with_cname(Message, _Qtype, _Host, _CnameChain, _MatchedRecords, _Zone, _CnameRecords, true) ->
  lager:info("CNAME loop detected (exact match)"),
  Message#dns_message{aa = true, rc = ?DNS_RCODE_SERVFAIL};
% No CNAME loop, follow the alias
resolve_exact_match_with_cname(Message, Qtype, Host, CnameChain, _MatchedRecords, Zone, CnameRecords, false) ->
  CnameRecord = lists:last(CnameRecords),
  Name = CnameRecord#dns_rr.data#dns_rrdata_cname.dname,
  lager:info("Restarting query with CNAME name ~p (exact match)", [Name]),
  case in_zone(Name, Zone) of
    true ->
      lager:info("In current zone"),
      resolve(Message#dns_message{aa = true, answers = Message#dns_message.answers ++ CnameRecords}, Name, Qtype, Zone, Host, CnameChain ++ CnameRecords);
    false ->
      lager:info("Not in zone for ~p", [Name]),
      resolve(Message#dns_message{aa = true, answers = Message#dns_message.answers ++ CnameRecords}, Name, Qtype, find_zone(Name), Host, CnameChain ++ CnameRecords)
  end.

best_match_resolution(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone) ->
  lager:info("No exact match found, using ~p", [BestMatchRecords]),
  best_match_resolution(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, lists:filter(match_type(?DNS_TYPE_NS), BestMatchRecords)).

best_match_resolution(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, []) ->
  resolve_best_match(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone);
best_match_resolution(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, ReferralRecords) ->
  resolve_best_match_referral(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, ReferralRecords).

resolve_best_match(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone) ->
  lager:info("No referrals found"),
  resolve_best_match(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, lists:any(match_wildcard(), BestMatchRecords)).

%% It's a wildcard match
resolve_best_match(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, true) ->
  lager:info("Matched records are wildcard."),
  CnameRecords = lists:filter(match_type(?DNS_TYPE_CNAME), lists:map(replace_name(Qname), BestMatchRecords)),
  resolve_best_match_with_wildcard(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, CnameRecords);
resolve_best_match(Message, Qname, _Qtype, _Host, _CnameChain, _BestMatchRecords, Zone, false) ->
  lager:info("Matched records are not wildcard."),
  [Question|_] = Message#dns_message.questions,
  resolve_best_match_with_wildcard(Message, Zone, Qname =:= Question#dns_query.name).

resolve_best_match_with_wildcard(Message, _Zone, false) ->
  lager:info("Qname did not match query name"),
  {Authority, Additional} = erldns_records:root_hints(),
  Message#dns_message{authority=Authority, additional=Additional};
resolve_best_match_with_wildcard(Message, Zone, true) ->
  lager:info("Qname matched query name"),
  Authority = lists:filter(match_type(?DNS_TYPE_SOA), Zone#zone.records),
  Message#dns_message{rc = ?DNS_RCODE_NXDOMAIN, authority = Authority, aa = true}.

% It's not a wildcard CNAME
resolve_best_match_with_wildcard(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, []) ->
  lager:info("Wildcard is not CNAME"),
  TypeMatchedRecords = case Qtype of
    ?DNS_TYPE_ANY -> BestMatchRecords;
    _ -> lists:filter(match_type(Qtype), BestMatchRecords)
  end,
  TypeMatches = lists:map(replace_name(Qname), TypeMatchedRecords),
  resolve_best_match_with_wildcard(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, [], TypeMatches);

% It is a wildcard CNAME
resolve_best_match_with_wildcard(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, CnameRecords) ->
  resolve_best_match_with_wildcard_cname(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, CnameRecords).

resolve_best_match_with_wildcard(Message, _Qname, _Qtype, _Host, _CnameChain, _BestMatchRecords, Zone, _CnameRecords, []) ->
  Message#dns_message{aa = true, authority=lists:filter(match_type(?DNS_TYPE_SOA), Zone#zone.records)};
resolve_best_match_with_wildcard(Message, _Qname, _Qtype, _Host, _CnameChain, _BestMatchRecords, _Zone, _CnameRecords, TypeMatches) ->
  Message#dns_message{aa = true, answers = Message#dns_message.answers ++ TypeMatches}.


resolve_best_match_with_wildcard_cname(Message, _Qname, ?DNS_TYPE_CNAME, _Host, _CnameChain, _BestMatchRecords, _Zone, CnameRecords) ->
  Message#dns_message{aa = true, answers = Message#dns_message.answers ++ CnameRecords};
resolve_best_match_with_wildcard_cname(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, CnameRecords) ->
  CnameRecord = lists:last(CnameRecords),
  resolve_best_match_with_wildcard_cname(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, CnameRecords, lists:member(CnameRecord, CnameChain)).

% Indicates CNAME loop
resolve_best_match_with_wildcard_cname(Message, _Qname, _Qtype, _Host, _CnameChain, _BestMatchRecords, _Zone, _CnameRecords, true) ->
  lager:info("CNAME loop detected (best match)"),
  Message#dns_message{aa = true, rc = ?DNS_RCODE_SERVFAIL};
% We should follow the CNAME
resolve_best_match_with_wildcard_cname(Message, _Qname, Qtype, Host, CnameChain, _BestMatchRecords, Zone, CnameRecords, false) ->
  lager:info("Follow CNAME (best match)"),
  CnameRecord = lists:last(CnameRecords),
  Name = CnameRecord#dns_rr.data#dns_rrdata_cname.dname,
  case in_zone(Name, Zone) of
    true ->
      lager:info("Restarting resolve with ~p using the current zone", [Name]),
      resolve(Message#dns_message{aa = true, answers = Message#dns_message.answers ++ [CnameRecord]}, Name, Qtype, Zone, Host, CnameChain ++ [CnameRecord]);
    false ->
      lager:info("Restarting resolve with ~p finding a new zone", [Name]),
      resolve(Message#dns_message{aa = true, answers = Message#dns_message.answers ++ [CnameRecord]}, Name, Qtype, find_zone(Name), Host, CnameChain ++ [CnameRecord])
  end.

% There are referral records
resolve_best_match_referral(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, ReferralRecords) ->
  resolve_best_match_referral(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, ReferralRecords, lists:filter(match_type(?DNS_TYPE_SOA), BestMatchRecords)).

% Indicate that we are not authoritative for the name.
resolve_best_match_referral(Message, _Qname, _Qtype, _Host, _CnameChain, _BestMatchRecords, _Zone, ReferralRecords, []) ->
  Message#dns_message{aa = false, authority = Message#dns_message.authority ++ ReferralRecords};
% We are authoritative for the name
resolve_best_match_referral(Message, _Qname, _Qtype, _Host, [], _BestMatchRecords, _Zone, _ReferralRecords, Authority) ->
  Message#dns_message{aa = true, rc = ?DNS_RCODE_NXDOMAIN, authority = Authority};
resolve_best_match_referral(Message, _Qname, ?DNS_TYPE_ANY, _Host, _CnameChain, _BestMatchRecords, _Zone, _ReferralRecords, _Authority) ->
   Message;
resolve_best_match_referral(Message, _Qname, _Qtype, _Host, _CnameChain, _BestMatchRecords, _Zone, _ReferralRecords, Authority) ->
  Message#dns_message{authority = Authority}.

%% Find the best match records for the given Qname in the
%% given zone. This will attempt to walk through the
%% domain hierarchy in the Qname looking for both exact and
%% wildcard matches.
best_match(Qname, Zone) -> best_match(Qname, dns:dname_to_labels(Qname), Zone).

best_match(_Qname, [], _Zone) -> [];
best_match(Qname, [_|Rest], Zone) ->
  WildcardName = dns:labels_to_dname([<<"*">>] ++ Rest),
  best_match(Qname, Rest, Zone, find_records_by_name(WildcardName, Zone)).

best_match(_Qname, [], _Zone, []) -> [];
best_match(Qname, Labels, Zone, []) ->
  Name = dns:labels_to_dname(Labels),
  case find_records_by_name(Name, Zone) of
    [] -> best_match(Qname, Labels, Zone);
    Matches -> Matches
  end;
best_match(_Qname, _Labels, _Zone, WildcardMatches) -> WildcardMatches.

%% Various matching functions.
match_type(Type) -> fun(R) when is_record(R, dns_rr) -> R#dns_rr.type =:= Type end.
match_wildcard() -> fun(R) when is_record(R, dns_rr) -> lists:any(fun(L) -> L =:= <<"*">> end, dns:dname_to_labels(R#dns_rr.name)) end.
match_glue(Name) -> fun(R) when is_record(R, dns_rr) -> R#dns_rr.data =:= #dns_rrdata_ns{dname=Name} end.

%% Replacement functions.
replace_name(Name) -> fun(R) when is_record(R, dns_rr) -> R#dns_rr{name = Name} end.

%% Find all delegation records for the given Name in the provided
%% Records. This function may return an empty list, which means
%% the record is not a glue record.
delegation_records(Name, Records) -> lists:filter(fun(R) -> apply(match_type(?DNS_TYPE_NS), [R]) and apply(match_glue(Name), [R]) end, Records).

normalize_name(Name) when is_list(Name) -> string:to_lower(Name);
normalize_name(Name) when is_binary(Name) -> list_to_binary(string:to_lower(binary_to_list(Name))).

%% See if additional processing is necessary.
additional_processing(Message, Host, Zone) ->
  RequiresAdditionalProcessing = erldns_metrics:measure(none, ?MODULE, requires_additional_processing, [Message#dns_message.answers ++ Message#dns_message.authority, []]),
  erldns_metrics:measure(none, ?MODULE, additional_processing, [Message, Host, Zone, lists:flatten(RequiresAdditionalProcessing)]).
%% No records require additional processing.
additional_processing(Message, _Host, _Zone, []) ->
  Message;
%% There are records with names that require additional processing.
additional_processing(Message, Host, Zone, Names) ->
  lager:debug("Doing additional processing on ~p", [Names]),
  RRs = lists:flatten(lists:map(fun(Name) -> find_records_by_name(Name, Zone) end, Names)),
  lager:debug("Records: ~p", [RRs]),
  Records = lists:filter(match_type(?DNS_TYPE_A), RRs),
  additional_processing(Message, Host, Zone, Names, Records).
%% No additional A records were found, so just return the message.
additional_processing(Message, _Host, _Zone, _Names, []) ->
  Message;
%% Additional A records were found, so we add them to the additional section.
additional_processing(Message, _Host, _Zone, _Names, Records) ->
  lager:debug("Additional processing, found ~p records", [length(Records)]),
  Additional = Message#dns_message.additional ++ Records,
  AdditionalCount = length(Additional),
  Message#dns_message{adc=AdditionalCount, additional=Additional}.

%% Given a list of answers find the names that require additional processing.
requires_additional_processing([], RequiresAdditional) -> RequiresAdditional;
requires_additional_processing([Answer|Rest], RequiresAdditional) ->
  Names = case Answer#dns_rr.data of
    Data when is_record(Data, dns_rrdata_ns) -> [Data#dns_rrdata_ns.dname];
    Data when is_record(Data, dns_rrdata_mx) -> [Data#dns_rrdata_mx.exchange];
    _ -> []
  end,
  requires_additional_processing(Rest, RequiresAdditional ++ Names).

%% Retreive all answers to the specific question.
answer_question(Qname, Qtype = ?DNS_TYPE_AXFR_NUMBER, Host, Message) ->
  lager:info("Answers AXFR question for host ~p", [Host]),
  answer_question(Qname, Qtype, Host, Message, erldns_axfr:is_enabled(Host, get_metadata(Qname, Message)));
answer_question(Qname, Qtype, _, Message) ->
  query_responders(Qname, Qtype, Message).

answer_question(Qname, Qtype = ?DNS_TYPE_AXFR, _Host, Message, true) ->
  query_responders(Qname, Qtype, Message);
answer_question(_Qname, ?DNS_TYPE_AXFR, _Host, _Message, false) ->
  lager:info("AXFR not allowed."),
  [].

%% Check all of the questions against all of the responders.
%% TODO: optimize to return first match
%% TODO: rescue from case where soa function is not defined.
get_soas(Message) ->
  lists:flatten(lists:map(fun(Q) -> [F([normalize_name(Q#dns_query.name)], Message) || F <- soa_functions()] end, Message#dns_message.questions)).

%% Get metadata for the domain connected to the given query name.
get_metadata(Qname, Message) ->
  lists:merge([F(Qname, Message) || F <- metadata_functions()]).

in_zone(Name, Zone) ->
  case dict:is_key(Name, Zone#zone.records_by_name) of
    true -> true;
    false ->
      case dns:dname_to_labels(Name) of
        [] -> false;
        [_] -> false;
        [_|Labels] -> in_zone(dns:labels_to_dname(Labels), Zone)
      end
  end.

%% Find the zone for the given name.
find_zone(Qname) ->
  DbRecords = erldns_metrics:measure(Qname, erldns_pgsql, lookup_records, [normalize_name(Qname)]),
  Records = lists:usort(lists:flatten(lists:map(fun(R) -> erldns_pgsql_responder:db_to_record(Qname, R) end, DbRecords))),
  RecordsByName = erldns_metrics:measure(Qname, ?MODULE, build_named_index, [Records]),
  #zone{records = Records, records_by_name = RecordsByName}.

find_records_by_name(Name, Zone) ->
  case dict:find(normalize_name(Name), Zone#zone.records_by_name) of
    {ok, RecordSet} -> RecordSet;
    error -> []
  end.

build_named_index(Records) -> build_named_index(Records, dict:new()).
build_named_index([], Idx) -> Idx;
build_named_index([R|Rest], Idx) ->
  case dict:find(R#dns_rr.name, Idx) of
    {ok, Records} ->
      build_named_index(Rest, dict:store(R#dns_rr.name, Records ++ [R], Idx));
    error -> build_named_index(Rest, dict:store(R#dns_rr.name, [R], Idx))
  end.

%% Get the answers for a query from the responders.
query_responders(Qname, Qtype, Message) ->
  query_responders(Qname, Qtype, Message, answer_functions()).
query_responders(_Qname, _Qtype, _Message, []) -> [];
query_responders(Qname, Qtype, Message, [F|AnswerFunctions]) ->
  case Answers = F(Qname, dns:type_name(Qtype), Message) of
    [] -> query_responders(Qname, Qtype, Message, AnswerFunctions);
    _ -> Answers
  end.

%% Update the message counts and set the QR flag to true.
complete_response(Message) ->
   Message#dns_message{
    anc = length(Message#dns_message.answers),
    auc = length(Message#dns_message.authority),
    adc = length(Message#dns_message.additional),
    qr = true
  }.

%% According to RFC 2308 the TTL for the SOA record in an NXDOMAIN response
%% must be set to the value of the minimum field in the SOA content.
rewrite_soa_ttl(Message) -> rewrite_soa_ttl(Message, Message#dns_message.authority, []).
rewrite_soa_ttl(Message, [], NewAuthority) -> Message#dns_message{authority = NewAuthority};
rewrite_soa_ttl(Message, [R|Rest], NewAuthority) ->
  Rdata = R#dns_rr.data,
  Record = case Rdata of
    Data when is_record(Data, dns_rrdata_soa) -> R#dns_rr{ttl = erlang:min(Data#dns_rrdata_soa.minimum, R#dns_rr.ttl)};
    _ -> R
  end,
  rewrite_soa_ttl(Message, Rest, NewAuthority ++ [Record]).

%% Build a list of answer functions based on the registered responders.
answer_functions() ->
  lists:map(fun(M) -> fun M:answer/3 end, get_responder_modules()).

%% Build a list of functions for looking up SOA records based on the
%% registered responders.
soa_functions() ->
  lists:map(fun(M) -> fun M:get_soa/2 end, get_responder_modules()).

%% Build a list of functions for getting metdata based on the registered
%% responders.
metadata_functions() ->
  lists:map(fun(M) -> fun M:get_metadata/2 end, get_responder_modules()).

%% Find the responder module names from the app environment. Default 
%% to just the erldns_mysql_responder.
get_responder_modules() -> get_responder_modules(application:get_env(erldns, responders)).
get_responder_modules({ok, RM}) -> RM;
get_responder_modules(_) -> [erldns_mysql_responder].
