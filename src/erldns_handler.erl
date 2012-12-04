-module(erldns_handler).

-include("dns.hrl").
-include("erldns.hrl").

-export([handle/2]).

% Internal API
-export([resolve/3, find_zone/1]).

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

handle_packet_cache_miss(Message, _, Host, Authoritative) ->
  case application:get_env(erldns, catch_exceptions) of
    {ok, false} -> maybe_cache_packet(resolve(Message, Host), Authoritative);
    _ ->
      try resolve(Message, Host) of
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
resolve(Message, Host) -> resolve(Message, Host, Message#dns_message.questions).

resolve(Message, _Host, []) -> Message;
resolve(Message, Host, [Question]) -> erldns_metrics:measure(Question#dns_query.name, ?MODULE, resolve, [Message, Host, Question]);
resolve(Message, Host, [Question|_]) -> erldns_metrics:measure(Question#dns_query.name, ?MODULE, resolve, [Message, Host, Question]);
resolve(Message, Host, Question) when is_record(Question, dns_query) ->
  % Step 1: Set the RA bit to false
  resolve(Message#dns_message{ra = false}, Question#dns_query.name, Question#dns_query.type, Host).

resolve(Message, Qname, Qtype, Host) ->
  % Step 2: Search the available zones for the zone which is the nearest ancestor to QNAME
  Records = find_zone(Qname),
  additional_processing(
    rewrite_soa_ttl(
      resolve(Message, Qname, Qtype, Records, Host, [])
    ), Host
  ).

resolve(Message, Qname, Qtype, Records, Host, CnameChain) ->
  lager:info("Zone has ~p records", [length(Records)]),
  % Step 3: Match records
  AllRecords = lists:usort(lists:flatten(lists:map(fun(R) -> erldns_pgsql_responder:db_to_record(Qname, R) end, Records))),
  resolve(Message, Qname, Qtype, Records, Host, CnameChain, AllRecords, lists:filter(match_name(Qname), AllRecords)).

%% There were no exact matches on name, so move to the best-match resolution.
resolve(Message, Qname, Qtype, _Records, Host, CnameChain, AllRecords, []) ->
  best_match_resolution(Message, Qname, Qtype, Host, CnameChain, best_match(Qname, AllRecords), AllRecords);
%% There was at least one exact match on name.
resolve(Message, Qname, Qtype, _Records, Host, CnameChain, AllRecords, MatchedRecords) ->
  exact_match_resolution(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, AllRecords).

%% Determine if there is a CNAME anywhere in the records with the given Qname.
exact_match_resolution(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, AllRecords) ->
  exact_match_resolution(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, AllRecords, lists:filter(match_type(?DNS_TYPE_CNAME), MatchedRecords)).
%% No CNAME records found in the records with the Qname
exact_match_resolution(Message, _Qname, Qtype, Host, CnameChain, MatchedRecords, AllRecords, []) ->
  resolve_exact_match(Message, Qtype, Host, CnameChain, MatchedRecords, AllRecords);
%% CNAME records found in the records for the Qname
exact_match_resolution(Message, _Qname, Qtype, Host, CnameChain, MatchedRecords, _AllRecords, CnameRecords) ->
  resolve_exact_match_with_cname(Message, Qtype, Host, CnameChain, MatchedRecords, CnameRecords).

%% There were no CNAMEs found in the exact name matches, so now we grab the authority
%% records and find any type matches on QTYPE and continue on.
resolve_exact_match(Message, Qtype, Host, CnameChain, MatchedRecords, AllRecords) ->
  AuthorityRecords = lists:filter(match_type(?DNS_TYPE_SOA), MatchedRecords),
  TypeMatches = lists:filter(match_type(Qtype), MatchedRecords),
  resolve_exact_match(Message, Qtype, Host, CnameChain, MatchedRecords, AllRecords, TypeMatches, AuthorityRecords).

resolve_exact_match(Message, Qtype, Host, CnameChain, MatchedRecords, AllRecords, [], AuthorityRecords) ->
  ReferralRecords = lists:filter(match_type(?DNS_TYPE_NS), MatchedRecords),
  resolve_no_exact_type_match(Message, Qtype, Host, CnameChain, [], AllRecords, MatchedRecords, ReferralRecords, AuthorityRecords);
resolve_exact_match(Message, Qtype, Host, CnameChain, _MatchedRecords, AllRecords, ExactTypeMatches, AuthorityRecords) ->
  resolve_exact_type_match(Message, Qtype, Host, CnameChain, ExactTypeMatches, AllRecords, AuthorityRecords).

resolve_exact_type_match(Message, ?DNS_TYPE_NS, Host, CnameChain, MatchedRecords, _AllRecords, []) ->
  Answer = lists:last(MatchedRecords),
  Name = Answer#dns_rr.name,
  lager:debug("Restarting query with delegated name ~p", [Name]),
  % It isn't clear what the QTYPE should be on a delegated restart. I assume an A record.
  resolve(Message, Name, ?DNS_TYPE_A, find_zone(Name), Host, CnameChain);
resolve_exact_type_match(Message, ?DNS_TYPE_NS, _Host, _CnameChain, MatchedRecords, _AllRecords, _AuthorityRecords) ->
  lager:debug("Authoritative for record, returning answers"),
  Message#dns_message{aa = true, rc = ?DNS_RCODE_NOERROR, answers = Message#dns_message.answers ++ MatchedRecords};
resolve_exact_type_match(Message, Qtype, Host, CnameChain, MatchedRecords, AllRecords, _AuthorityRecords) ->
  Answer = lists:last(MatchedRecords),
  NSRecords = delegation_records(Answer#dns_rr.name, AllRecords),
  resolve_exact_type_match(Message, Qtype, Host, CnameChain, MatchedRecords, AllRecords, _AuthorityRecords, NSRecords).

resolve_exact_type_match(Message, _Qtype, _Host, _CnameChain, MatchedRecords, _AllRecords, _AuthorityRecords, []) ->
  lager:debug("Returning authoritative answer with ~p appended answers", [length(MatchedRecords)]),
  Message#dns_message{aa = true, rc = ?DNS_RCODE_NOERROR, answers = Message#dns_message.answers ++ MatchedRecords};
resolve_exact_type_match(Message, Qtype, Host, CnameChain, _MatchedRecords, _AllRecords, _AuthorityRecords, NSRecords) ->
  NSRecord = lists:last(NSRecords),
  DelegatedName = NSRecord#dns_rr.name,
  lager:debug("Restarting query with delegated name ~p", [DelegatedName]),
  resolve(Message, DelegatedName, Qtype, find_zone(DelegatedName), Host, CnameChain).

resolve_no_exact_type_match(Message, ?DNS_TYPE_ANY, _Host, _CnameChain, _ExactTypeMatches, _AllRecords, [], [], AuthorityRecords) ->
  Message#dns_message{aa = true, authority = AuthorityRecords};
resolve_no_exact_type_match(Message, _Qtype, _Host, _CnameChain, [], AllRecords, _MatchedRecords, [], _AuthorityRecords) ->
  Message#dns_message{aa = true, authority = lists:filter(match_type(?DNS_TYPE_SOA), AllRecords)};
resolve_no_exact_type_match(Message, _Qtype, _Host, _CnameChain, ExactTypeMatches, _AllRecords, _MatchedRecords, [], _AuthorityRecords) ->
  Message#dns_message{aa = true, answers = Message#dns_message.answers ++ ExactTypeMatches};
resolve_no_exact_type_match(Message, Qtype, _Host, _CnameChain, _ExactTypeMatches, _AllRecords, MatchedRecords, ReferralRecords, AuthorityRecords) ->
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
resolve_exact_match_with_cname(Message, ?DNS_TYPE_CNAME, _Host, _CnameChain, _MatchedRecords, CnameRecords) ->
  Message#dns_message{aa = true, answers = Message#dns_message.answers ++ CnameRecords};
% There is a CNAME record, however the type is not CNAME, check for a CNAME loop before continuing
resolve_exact_match_with_cname(Message, Qtype, Host, CnameChain, MatchedRecords, CnameRecords) ->
  resolve_exact_match_with_cname(Message, Qtype, Host, CnameChain, MatchedRecords, CnameRecords, lists:member(lists:last(CnameRecords), CnameChain)).

%% Indicates a CNAME loop
resolve_exact_match_with_cname(Message, _Qtype, _Host, _CnameChain, _MatchedRecords, _CnameRecords, true) ->
  Message#dns_message{aa = true, rc = ?DNS_RCODE_SERVFAIL};
% No CNAME loop, follow the alias
resolve_exact_match_with_cname(Message, Qtype, Host, CnameChain, _MatchedRecords, CnameRecords, false) ->
  CnameRecord = lists:last(CnameRecords),
  Name = CnameRecord#dns_rr.data#dns_rrdata_cname.dname,
  lager:debug("Restarting query with CNAME name ~p", [Name]),
  resolve(Message#dns_message{aa = true, answers = Message#dns_message.answers ++ CnameRecords}, Name, Qtype, find_zone(Name), Host, CnameChain ++ CnameRecords).

best_match_resolution(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, AllRecords) ->
  lager:debug("No exact match found, using ~p", [BestMatchRecords]),
  best_match_resolution(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, AllRecords, lists:filter(match_type(?DNS_TYPE_NS), BestMatchRecords)).

best_match_resolution(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, AllRecords, []) ->
  resolve_best_match(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, AllRecords);
best_match_resolution(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, AllRecords, ReferralRecords) ->
  resolve_best_match_referral(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, AllRecords, ReferralRecords).

resolve_best_match(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, AllRecords) ->
  lager:debug("No referrals found"),
  resolve_best_match(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, AllRecords, lists:any(match_wildcard(), BestMatchRecords)).

%% It's a wildcard match
resolve_best_match(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, AllRecords, true) ->
  CnameRecords = lists:filter(match_type(?DNS_TYPE_CNAME), lists:map(replace_name(Qname), BestMatchRecords)),
  resolve_best_match_with_wildcard(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, AllRecords, CnameRecords);
resolve_best_match(Message, Qname, _Qtype, _Host, _CnameChain, _BestMatchRecords, AllRecords, false) ->
  lager:debug("Matched records are not wildcard."),
  [Question|_] = Message#dns_message.questions,
  resolve_best_match_with_wildcard(Message, AllRecords, Qname =:= Question#dns_query.name).

% It's not a wildcard CNAME
resolve_best_match_with_wildcard(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, AllRecords, []) ->
  lager:debug("Wildcard is not CNAME"),
  TypeMatchedRecords = case Qtype of
    ?DNS_TYPE_ANY -> BestMatchRecords;
    _ -> lists:filter(match_type(Qtype), BestMatchRecords)
  end,
  TypeMatches = lists:map(replace_name(Qname), TypeMatchedRecords),
  resolve_best_match_with_wildcard(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, AllRecords, [], TypeMatches);

% It is a wildcard CNAME
resolve_best_match_with_wildcard(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, _AllRecords, CnameRecords) ->
  resolve_best_match_with_wildcard_cname(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, CnameRecords).

resolve_best_match_with_wildcard(Message, _Qname, _Qtype, _Host, _CnameChain, _BestMatchRecords, AllRecords, _CnameRecords, []) ->
  Message#dns_message{aa = true, authority=lists:filter(match_type(?DNS_TYPE_SOA), AllRecords)};
resolve_best_match_with_wildcard(Message, _Qname, _Qtype, _Host, _CnameChain, _BestMatchRecords, _AllRecords, _CnameRecords, TypeMatches) ->
  Message#dns_message{aa = true, answers = Message#dns_message.answers ++ TypeMatches}.

resolve_best_match_with_wildcard(Message, _AllRecords, false) ->
  {Authority, Additional} = erldns_records:root_hints(),
  Message#dns_message{authority=Authority, additional=Additional};
resolve_best_match_with_wildcard(Message, AllRecords, true) ->
  Authority = lists:filter(match_type(?DNS_TYPE_SOA), AllRecords),
  Message#dns_message{rc = ?DNS_RCODE_NXDOMAIN, authority = Authority, aa = true}.

resolve_best_match_with_wildcard_cname(Message, _Qname, ?DNS_TYPE_CNAME, _Host, _CnameChain, _BestMatchRecords, CnameRecords) ->
  Message#dns_message{aa = true, answers = Message#dns_message.answers ++ CnameRecords};
resolve_best_match_with_wildcard_cname(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, CnameRecords) ->
  lager:debug("Found CNAME, but qtype is ~p", [Qtype]),
  CnameRecord = lists:last(CnameRecords),
  resolve_best_match_with_wildcard_cname(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, CnameRecords, lists:member(CnameRecord, CnameChain)).

% Indicates CNAME loop
resolve_best_match_with_wildcard_cname(Message, _Qname, _Qtype, _Host, _CnameChain, _BestMatchRecords, _CnameRecords, true) ->
  Message#dns_message{aa = true, rc = ?DNS_RCODE_SERVFAIL};
% We should follow the CNAME
resolve_best_match_with_wildcard_cname(Message, _Qname, Qtype, Host, CnameChain, _BestMatchRecords, CnameRecords, false) ->
  CnameRecord = lists:last(CnameRecords),
  Name = CnameRecord#dns_rr.data#dns_rrdata_cname.dname,
  lager:debug("Restarting resolve with ~p", [Name]),
  resolve(Message#dns_message{aa = true, answers = Message#dns_message.answers ++ [CnameRecord]}, Name, Qtype, find_zone(Name), Host, CnameChain ++ [CnameRecord]).

% There are referral records
resolve_best_match_referral(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, AllRecords, ReferralRecords) ->
  resolve_best_match_referral(Message, Qname, Qtype, Host,  CnameChain, BestMatchRecords, AllRecords, ReferralRecords, lists:filter(match_type(?DNS_TYPE_SOA), BestMatchRecords)).

% Indicate that we are not authoritative for the name.
resolve_best_match_referral(Message, _Qname, _Qtype, _Host, _CnameChain, _BestMatchRecords, _AllRecords, ReferralRecords, []) ->
  Message#dns_message{aa = false, authority = Message#dns_message.authority ++ ReferralRecords};
% We are authoritative for the name
resolve_best_match_referral(Message, _Qname, _Qtype, _Host, [], _BestMatchRecords, _AllRecords, _ReferralRecords, Authority) ->
  Message#dns_message{aa = true, rc = ?DNS_RCODE_NXDOMAIN, authority = Authority};
resolve_best_match_referral(Message, _Qname, ?DNS_TYPE_ANY, _Host, _CnameChain, _BestMatchRecords, _AllRecords, _ReferralRecords, _Authority) ->
   Message;
resolve_best_match_referral(Message, _Qname, _Qtype, _Host, _CnameChain, _BestMatchRecords, _AllRecords, _ReferralRecords, Authority) ->
  Message#dns_message{authority = Authority}.

%% Find the best match records for the given Qname in the
%% given Record set. This will attempt to walk through the
%% domain hierarchy in the Qname looking for both exact and
%% wildcard matches.
best_match(Qname, Records) -> best_match(Qname, dns:dname_to_labels(Qname), Records).

best_match(_Qname, [], _Records) -> [];
best_match(Qname, [_|Rest], Records) ->
  WildcardName = dns:labels_to_dname([<<"*">>] ++ Rest),
  best_match(Qname, Rest, Records, lists:filter(match_name(WildcardName), Records)).

best_match(_Qname, [], _Records, []) -> [];
best_match(Qname, Labels, Records, []) ->
  Name = dns:labels_to_dname(Labels),
  case lists:filter(match_name(Name), Records) of
    [] -> best_match(Qname, Labels, Records);
    Matches -> Matches
  end;
best_match(_Qname, _Labels, _Records, WildcardMatches) -> WildcardMatches.

%% Various matching functions.
match_type(Type) -> fun(R) when is_record(R, dns_rr) -> R#dns_rr.type =:= Type end.
match_name(Name) -> fun(R) when is_record(R, dns_rr) -> R#dns_rr.name =:= normalize_name(Name) end.
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
additional_processing(Message, Host) ->
  additional_processing(Message, Host, lists:flatten(requires_additional_processing(Message#dns_message.answers ++ Message#dns_message.authority, []))).
%% No records require additional processing.
additional_processing(Message, _Host, []) ->
  Message;
%% There are records with names that require additional processing.
additional_processing(Message, Host, Names) ->
  lager:debug("Doing additional processing on ~p", [Names]),
  additional_processing(Message, Host, Names, lists:flatten(lists:map(fun(Qname) -> answer_question(Qname, ?DNS_TYPE_A, Host, Message) end, Names))).
%% No additional A records were found, so just return the message.
additional_processing(Message, _Host, _Names, []) ->
  Message;
%% Additional A records were found, so we add them to the additional section.
additional_processing(Message, _Host, _Names, Records) ->
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

%% Find the zone for the given name.
find_zone(Qname) ->
  erldns_metrics:measure(lists:concat(["find_zone: ", binary_to_list(Qname)]), erldns_pgsql, lookup_records, [normalize_name(Qname)]).

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
