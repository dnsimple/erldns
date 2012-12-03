-module(erldns_handler).

-include("dns.hrl").
-include("erldns.hrl").

-export([handle/2]).

% Internal API
-export([resolve/3]).

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

handle_packet_cache_miss(Message, [], _Host) ->
  {Authority, Additional} = erldns_records:root_hints(),
  Message#dns_message{aa = false, rc = ?DNS_RCODE_NOERROR, authority = Authority, additional = Additional};
handle_packet_cache_miss(Message, _, Host) ->
  Message2 = Message#dns_message{ra = false},
  case application:get_env(erldns, catch_exceptions) of
    {ok, false} -> maybe_cache_packet(resolve(Message2, Host));
    _ ->
      try resolve(Message2, Host) of
        Response -> maybe_cache_packet(Response)
      catch
        Exception:Reason ->
          lager:error("Error answering request: ~p (~p)", [Exception, Reason]),
          Message2#dns_message{aa = false, rc = ?DNS_RCODE_SERVFAIL}
      end
  end.

maybe_cache_packet(Message) ->
  case Message#dns_message.aa of
    true -> erldns_packet_cache:put(Message#dns_message.questions, Message);
    _ -> ok
  end,
  Message.

find_zone(Qname) ->
  erldns_pgsql:lookup_records(normalize_name(Qname)).

measure(Name, FunctionName, Args) when is_list(Args) ->
  {T, R} = timer:tc(?MODULE, FunctionName, Args),
  erldns_metrics:insert(Name, T),
  lager:info("~p took ~p ms", [FunctionName, T / 1000]),
  R;
measure(Name, FunctionName, Arg) -> measure(Name, FunctionName, [Arg]).

%% Resolve the first question inside the given message.
resolve(Message, Host) -> resolve(Message, Host, Message#dns_message.questions).

resolve(Message, _Host, []) -> Message;
resolve(Message, Host, [Question]) -> measure(Question#dns_query.name, resolve, [Message, Host, Question]);
resolve(Message, Host, [Question|_]) -> measure(Question#dns_query.name, resolve, [Message, Host, Question]);
resolve(Message, Host, Question) when is_record(Question, dns_query) ->
  % Step 1: Set the RA bit to false
  resolve(Message#dns_message{ra = false}, Question#dns_query.name, Question#dns_query.type, Host).

resolve(Message, Qname, Qtype, Host) ->
  % Step 2: Search the available zones for the zone which is the nearest ancestor to QNAME
  Records = find_zone(Qname),
  lager:info("Zone has ~p records", [length(Records)]),
  additional_processing(
    rewrite_soa_ttl(
      resolve(Message, Qname, Qtype, Records, Host)
    ), Host
  ).

resolve(Message, Qname, Qtype, Records, Host) -> resolve(Message, Qname, Qtype, Records, Host, false, []).

resolve(Message, Qname, Qtype, Records, Host, Wildcard, CnameChain) ->
  % Step 3: Match records
  AllRecords = lists:usort(lists:flatten(lists:map(fun(R) -> erldns_pgsql_responder:db_to_record(Qname, R) end, Records))),
  resolve(Message, Qname, Qtype, Records, Host, Wildcard, CnameChain, AllRecords, lists:filter(match_name(Qname), AllRecords)). 

resolve(Message, Qname, Qtype, _Records, Host, Wildcard, CnameChain, AllRecords, []) ->
  best_match_resolution(Message, Qname, Qtype, Host, Wildcard, CnameChain, best_match(Qname, AllRecords), AllRecords);
resolve(Message, Qname, Qtype, _Records, Host, Wildcard, CnameChain, AllRecords, MatchedRecords) ->
  exact_match_resolution(Message, Qname, Qtype, Host, Wildcard, CnameChain, MatchedRecords, AllRecords).


exact_match_resolution(Message, _Qname, Qtype, Host, Wildcard, CnameChain, MatchedRecords, AllRecords) ->
  lager:debug("Exact matches found: ~p", [length(MatchedRecords)]),
  CnameRecords = lists:filter(match_type(?DNS_TYPE_CNAME), MatchedRecords),
  case length(CnameRecords) > 0 of
    true -> resolve_exact_match_with_cname(Message, Qtype, Host, Wildcard, CnameChain, MatchedRecords, CnameRecords);
    false -> resolve_exact_match(Message, Qtype, Host, Wildcard, CnameChain, MatchedRecords, AllRecords)
  end.

resolve_exact_match(Message, Qtype, Host, Wildcard, CnameChain, MatchedRecords, AllRecords) ->
  lager:debug("No CNAME records found in matches"),
  AuthorityRecords = lists:filter(match_type(?DNS_TYPE_SOA), MatchedRecords),
  ExactTypeMatches = lists:filter(match_type(Qtype), MatchedRecords),
  resolve_exact_match(Message, Qtype, Host, Wildcard, CnameChain, MatchedRecords, AllRecords, ExactTypeMatches, AuthorityRecords).

resolve_exact_match(Message, Qtype, Host, Wildcard, CnameChain, MatchedRecords, AllRecords, [], AuthorityRecords) ->
  ReferralRecords = lists:filter(match_type(?DNS_TYPE_NS), MatchedRecords),
  resolve_no_exact_type_match(Message, Qtype, Host, Wildcard, CnameChain, [], AllRecords, MatchedRecords, ReferralRecords, AuthorityRecords);
resolve_exact_match(Message, Qtype, Host, Wildcard, CnameChain, _MatchedRecords, AllRecords, ExactTypeMatches, AuthorityRecords) ->
  resolve_exact_type_match(Message, Qtype, Host, Wildcard, CnameChain, ExactTypeMatches, AllRecords, AuthorityRecords).

resolve_exact_type_match(Message, ?DNS_TYPE_NS, Host, Wildcard, CnameChain, MatchedRecords, _AllRecords, []) ->
  Answer = lists:last(MatchedRecords),
  Name = Answer#dns_rr.name,
  lager:debug("Restarting query with delegated name ~p", [Name]),
  resolve(Message, Name, ?DNS_TYPE_A, find_zone(Name), Host, Wildcard, CnameChain);
resolve_exact_type_match(Message, ?DNS_TYPE_NS, _Host, _Wildcard, _CnameChain, MatchedRecords, _AllRecords, _AuthorityRecords) ->
  lager:debug("Authoritative for record, returning answers"),
  Message#dns_message{aa = true, rc = ?DNS_RCODE_NOERROR, answers = Message#dns_message.answers ++ MatchedRecords};
resolve_exact_type_match(Message, Qtype, Host, Wildcard, CnameChain, MatchedRecords, AllRecords, _AuthorityRecords) ->
  Answer = lists:last(MatchedRecords),
  NSRecords = delegation_records(Answer#dns_rr.name, AllRecords),
  resolve_exact_type_match(Message, Qtype, Host, Wildcard, CnameChain, MatchedRecords, AllRecords, _AuthorityRecords, NSRecords).

resolve_exact_type_match(Message, _Qtype, _Host, _Wildcard, _CnameChain, MatchedRecords, _AllRecords, _AuthorityRecords, []) ->
  lager:debug("Returning authoritative answer with ~p appended answers", [length(MatchedRecords)]),
  Message#dns_message{aa = true, rc = ?DNS_RCODE_NOERROR, answers = Message#dns_message.answers ++ MatchedRecords};
resolve_exact_type_match(Message, Qtype, Host, Wildcard, CnameChain, _MatchedRecords, _AllRecords, _AuthorityRecords, NSRecords) ->
  NSRecord = lists:last(NSRecords),
  DelegatedName = NSRecord#dns_rr.name,
  lager:debug("Restarting query with delegated name ~p", [DelegatedName]),
  resolve(Message, DelegatedName, Qtype, find_zone(DelegatedName), Host, Wildcard, CnameChain).


resolve_no_exact_type_match(Message, Qtype, _Host, _Wildcard, _CnameChain, ExactTypeMatches, AllRecords, MatchedRecords, [], _AuthorityRecords) ->
  lager:debug("No referrals"),
  Answers = case Qtype of
    ?DNS_TYPE_ANY -> MatchedRecords;
    _ -> ExactTypeMatches
  end,
  lager:debug("Type matches: ~p", [Answers]),
  case Answers of
    [] -> Message#dns_message{aa = true, authority = lists:filter(match_type(?DNS_TYPE_SOA), AllRecords)};
    _ -> Message#dns_message{aa = true, answers = Message#dns_message.answers ++ Answers}
  end;
resolve_no_exact_type_match(Message, Qtype, _Host, _Wildcard, _CnameChain, _ExactTypeMatches, _AllRecords, MatchedRecords, ReferralRecords, AuthorityRecords) ->
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

resolve_exact_match_with_cname(Message, ?DNS_TYPE_CNAME, _Host, _Wildcard, _CnameChain, _MatchedRecords, CnameRecords) ->
  Message#dns_message{aa = true, answers = Message#dns_message.answers ++ CnameRecords};
resolve_exact_match_with_cname(Message, Qtype, Host, Wildcard, CnameChain, MatchedRecords, CnameRecords) ->
  lager:debug("Found CNAME, but qtype is ~p", [Qtype]),
  resolve_exact_match_with_cname(Message, Qtype, Host, Wildcard, CnameChain, MatchedRecords, CnameRecords, lists:member(lists:last(CnameRecords), CnameChain)).

%% Indicates a CNAME loop
resolve_exact_match_with_cname(Message, _Qtype, _Host, _Wildcard, _CnameChain, _MatchedRecords, _CnameRecords, true) ->
  Message#dns_message{aa = true, rc = ?DNS_RCODE_SERVFAIL};
resolve_exact_match_with_cname(Message, Qtype, Host, Wildcard, CnameChain, _MatchedRecords, CnameRecords, false) ->
  CnameRecord = lists:last(CnameRecords),
  Name = CnameRecord#dns_rr.data#dns_rrdata_cname.dname,
  lager:debug("Restarting query with CNAME name ~p", [Name]),
  resolve(Message#dns_message{aa = true, answers = Message#dns_message.answers ++ CnameRecords}, Name, Qtype, find_zone(Name), Host, Wildcard, CnameChain ++ CnameRecords).

best_match_resolution(Message, Qname, Qtype, Host, _Wildcard, CnameChain, BestMatchRecords, AllRecords) ->
  lager:debug("No exact match found, using ~p", [BestMatchRecords]),
  best_match_resolution(Message, Qname, Qtype, Host, _Wildcard, CnameChain, BestMatchRecords, AllRecords, lists:filter(match_type(?DNS_TYPE_NS), BestMatchRecords)).

best_match_resolution(Message, Qname, Qtype, Host, _Wildcard, CnameChain, BestMatchRecords, AllRecords, []) ->
  resolve_best_match(Message, Qname, Qtype, Host, _Wildcard, CnameChain, BestMatchRecords, AllRecords);
best_match_resolution(Message, Qname, Qtype, Host, _Wildcard, CnameChain, BestMatchRecords, AllRecords, ReferralRecords) ->
  resolve_best_match_referral(Message, Qname, Qtype, Host, _Wildcard, CnameChain, BestMatchRecords, AllRecords, ReferralRecords).

resolve_best_match(Message, Qname, Qtype, Host, _Wildcard, CnameChain, BestMatchRecords, AllRecords) ->
  lager:debug("No referrals found"),
  IsWildcard = lists:any(match_wildcard(), BestMatchRecords),
  case IsWildcard of
    true ->
      lager:debug("Matched records are wildcard."),
      resolve_best_match(Message, Qname, Qtype, Host, IsWildcard, CnameChain, BestMatchRecords, AllRecords, lists:filter(match_type(?DNS_TYPE_CNAME), lists:map(replace_name(Qname), BestMatchRecords)));
    false ->
      lager:debug("Matched records are not wildcard."),
      [Question|_] = Message#dns_message.questions,
      case Qname =:= Question#dns_query.name of
        true ->
          Authority = lists:filter(match_type(?DNS_TYPE_SOA), AllRecords),
          Message#dns_message{rc = ?DNS_RCODE_NXDOMAIN, authority = Authority, aa = true};
        false ->
          {Authority, Additional} = erldns_records:root_hints(),
          Message#dns_message{authority=Authority, additional=Additional}
      end
  end.

resolve_best_match(Message, Qname, Qtype, _Host, _Wildcard, _CnameChain, BestMatchRecords, AllRecords, []) ->
  lager:debug("Wildcard is not CNAME"),
  TypeMatchedRecords = case Qtype of
    ?DNS_TYPE_ANY -> BestMatchRecords;
    _ -> lists:filter(match_type(Qtype), BestMatchRecords)
  end,
  TypeMatches = lists:map(replace_name(Qname), TypeMatchedRecords),
  case length(TypeMatches) of
    0 ->
      Authority = lists:filter(match_type(?DNS_TYPE_SOA), AllRecords),
      Message#dns_message{aa = true, authority=Authority};
    _ ->
      Message#dns_message{aa = true, answers = Message#dns_message.answers ++ TypeMatches}
  end;
resolve_best_match(Message, Qname, Qtype, Host, Wildcard, CnameChain, BestMatchRecords, _AllRecords, CnameRecords) ->
  resolve_best_match_with_wildcard_cname(Message, Qname, Qtype, Host, Wildcard, CnameChain, BestMatchRecords, CnameRecords).

resolve_best_match_with_wildcard_cname(Message, _Qname, ?DNS_TYPE_CNAME, _Host, _Wildcard, _CnameChain, _BestMatchRecords, CnameRecords) ->
  Message#dns_message{aa = true, answers = Message#dns_message.answers ++ CnameRecords};
resolve_best_match_with_wildcard_cname(Message, Qname, Qtype, Host, Wildcard, CnameChain, BestMatchRecords, CnameRecords) ->
  lager:debug("Found CNAME, but qtype is ~p", [Qtype]),
  CnameRecord = lists:last(CnameRecords),
  resolve_best_match_with_wildcard_cname(Message, Qname, Qtype, Host, Wildcard, CnameChain, BestMatchRecords, CnameRecords, lists:member(CnameRecord, CnameChain)).

% Indicates CNAME loop
resolve_best_match_with_wildcard_cname(Message, _Qname, _Qtype, _Host, _Wildcard, _CnameChain, _BestMatchRecords, _CnameRecords, true) ->
  Message#dns_message{aa = true, rc = ?DNS_RCODE_SERVFAIL};
% We should follow the CNAME
resolve_best_match_with_wildcard_cname(Message, _Qname, Qtype, Host, Wildcard, CnameChain, _BestMatchRecords, CnameRecords, false) ->
  CnameRecord = lists:last(CnameRecords),
  Name = CnameRecord#dns_rr.data#dns_rrdata_cname.dname,
  lager:debug("Restarting resolve with ~p", [Name]),
  resolve(Message#dns_message{aa = true, answers = Message#dns_message.answers ++ [CnameRecord]}, Name, Qtype, find_zone(Name), Host, Wildcard, CnameChain ++ [CnameRecord]).

% There are referral records
resolve_best_match_referral(Message, Qname, Qtype, Host, Wildcard, CnameChain, BestMatchRecords, AllRecords, ReferralRecords) ->
  resolve_best_match_referral(Message, Qname, Qtype, Host, Wildcard, CnameChain, BestMatchRecords, AllRecords, ReferralRecords, lists:filter(match_type(?DNS_TYPE_SOA), BestMatchRecords)).

% Indicate that we are not authoritative for the name.
resolve_best_match_referral(Message, _Qname, _Qtype, _Host, _Wildcard, _CnameChain, _BestMatchRecords, _AllRecords, ReferralRecords, []) ->
  Message#dns_message{aa = false, authority = Message#dns_message.authority ++ ReferralRecords};
% We are authoritative for the name
resolve_best_match_referral(Message, _Qname, _Qtype, _Host, _Wildcard, [], _BestMatchRecords, _AllRecords, _ReferralRecords, Authority) ->
  Message#dns_message{aa = true, rc = ?DNS_RCODE_NXDOMAIN, authority = Authority};
resolve_best_match_referral(Message, _Qname, ?DNS_TYPE_ANY, _Host, _Wildcard, _CnameChain, _BestMatchRecords, _AllRecords, _ReferralRecords, _Authority) ->
   Message;
resolve_best_match_referral(Message, _Qname, _Qtype, _Host, _Wildcard, _CnameChain, _BestMatchRecords, _AllRecords, _ReferralRecords, Authority) ->
  Message#dns_message{authority = Authority}.

%% Find the best match records for the given Qname in the
%% given Record set. This will attempt to walk through the
%% domain hierarchy in the Qname looking for both exact and
%% wildcard matches.
best_match(Qname, Records) -> best_match(Qname, dns:dname_to_labels(Qname), Records).

best_match(_Qname, [], _Records) -> [];
best_match(Qname, [_|Rest], Records) ->
  WildcardName = dns:labels_to_dname([<<"*">>] ++ Rest),
  case lists:filter(match_name(WildcardName), Records) of
    [] ->
      case Rest of
        [] -> [];
        _ ->
          Name = dns:labels_to_dname(Rest),
          case lists:filter(match_name(Name), Records) of
            [] -> best_match(Qname, Rest, Records);
            Matches -> Matches
          end
      end;
    Matches -> Matches
  end.

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

%% Check all of the questions against all of the responders.
%% TODO: optimize to return first match
%% TODO: rescue from case where soa function is not defined.
get_soas(Message) ->
  lists:flatten(lists:map(fun(Q) -> [F([normalize_name(Q#dns_query.name)], Message) || F <- soa_functions()] end, Message#dns_message.questions)).

%% Get metadata for the domain connected to the given query name.
get_metadata(Qname, Message) ->
  lists:merge([F(Qname, Message) || F <- metadata_functions()]).

%% Do additional processing
additional_processing(Message, Host) ->
  Names = lists:flatten(requires_additional_processing(Message#dns_message.answers ++ Message#dns_message.authority, [])),
  case Names of
    [] -> Message;
    _ ->
      lager:debug("Doing additional processing on ~p", [Names]),
      Records = lists:flatten(lists:map(
          fun(Qname) ->
              answer_question(Qname, ?DNS_TYPE_A, Host, Message)
          end, Names)),
      case Records of
        [] -> Message;
        _ ->
          lager:debug("Additional processing, found ~p records", [length(Records)]),
          Additional = Message#dns_message.additional ++ Records,
          AdditionalCount = length(Additional),
          Message#dns_message{adc=AdditionalCount, additional=Additional}
      end
  end.

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
  case erldns_axfr:is_enabled(Host, get_metadata(Qname, Message)) of
    true -> query_responders(Qname, Qtype, Message);
    _ ->
      lager:info("AXFR not allowed."),
      []
  end;
answer_question(Qname, Qtype, _, Message) ->
  query_responders(Qname, Qtype, Message).

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
