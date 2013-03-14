-module(erldns_handler).
-behavior(gen_server).

-include("dns.hrl").
-include("erldns.hrl").

-export([start_link/0, register_handler/2, handle/2]).

% Gen server hooks
-export([init/1,
	 handle_call/3,
	 handle_cast/2,
	 handle_info/2,
	 terminate/2,
	 code_change/3
       ]).

% Internal API
-export([resolve/4, resolve/6, handle_message/2, find_zone/2]).
-export([requires_additional_processing/2, additional_processing/3, additional_processing/4]).
-export([rewrite_soa_ttl/1]).

-record(state, {handlers}).

start_link() ->
  gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

register_handler(RecordTypes, Module) ->
  gen_server:call(?MODULE, {register_handler, RecordTypes, Module}).

get_handlers() ->
  gen_server:call(?MODULE, {get_handlers}).

init([]) ->
  lager:info("Initialized the handler_registry"),
  {ok, #state{handlers=[]}}.

handle_call({register_handler, RecordTypes, Module}, _, State) ->
  lager:info("Registered handler ~p for types ~p", [Module, RecordTypes]),
  {reply, ok, State#state{handlers = State#state.handlers ++ [{Module, RecordTypes}]}};
handle_call({get_handlers}, _, State) ->
  {reply, State#state.handlers, State}.

handle_cast(_, State) ->
  {noreply, State}.
handle_info(_, State) ->
  {noreply, State}.
terminate(_, _) ->
  ets:delete(handler_registry),
  ok.
code_change(_PreviousVersion, State, _Extra) ->
  {ok, State}.

%% If the message has trailing garbage just throw the garbage away and continue
%% trying to process the message.
handle({trailing_garbage, Message, _}, Host) ->
  handle(Message, Host);
%% Handle the message, checking to see if it is throttled.
handle(Message, Host) when is_record(Message, dns_message) ->
  handle(Message, Host, erldns_query_throttle:throttle(Message, Host));
%% The message was bad so just return it.
%% TODO: consider just throwing away the message
handle(BadMessage, Host) ->
  lager:error("Received a bad message: ~p from ~p", [BadMessage, Host]),
  BadMessage.

%% We throttle ANY queries to discourage use of our authoritative name servers
%% for reflection attacks.
handle(Message, Host, {throttled, Host, ReqCount}) ->
  lager:debug("Throttled ANY query for ~p. (req count: ~p)", [Host, ReqCount]),
  Message#dns_message{rc = ?DNS_RCODE_REFUSED};
%% Message was not throttled, so handle it, then do EDNS handling, optionally
%% append the SOA record if it is a zone transfer and complete the response
%% by filling out count-related header fields.
handle(Message, Host, _) ->
  lager:debug("Questions: ~p", [Message#dns_message.questions]),
  NewMessage = erldns_metrics:measure(none, ?MODULE, handle_message, [Message, Host]),
  complete_response(erldns_axfr:optionally_append_soa(erldns_edns:handle(NewMessage))).

%% Handle the message by hitting the packet cache and either
%% using the cached packet or continuing with the lookup process.
handle_message(Message, Host) ->
  case erldns_packet_cache:get(Message#dns_message.questions) of
    {ok, CachedResponse} -> CachedResponse#dns_message{id=Message#dns_message.id};
    {error, _} -> handle_packet_cache_miss(Message, get_authority(Message), Host) % SOA lookup
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

%% We are authoritative so cache the packet and return the message.
maybe_cache_packet(Message, true) ->
  erldns_packet_cache:put(Message#dns_message.questions, Message),
  Message;
%% We are not authoritative so just return the message.
maybe_cache_packet(Message, false) ->
  Message.

%% Resolve the first question inside the given message.
resolve(Message, AuthorityRecords, Host) -> 
  resolve(Message, AuthorityRecords, Host, Message#dns_message.questions).

%% There were no questions in the message so just return it.
resolve(Message, _AuthorityRecords, _Host, []) -> Message;
%% Resolve the question.
resolve(Message, AuthorityRecords, Host, [Question]) -> resolve(Message, AuthorityRecords, Host, Question);
%% Resolve the first question. Additional questions will be thrown away for now.
resolve(Message, AuthorityRecords, Host, [Question|_]) -> resolve(Message, AuthorityRecords, Host, Question);
%% Start the resolution process on the given question.
resolve(Message, AuthorityRecords, Host, Question) when is_record(Question, dns_query) ->
  % Step 1: Set the RA bit to false
  resolve(Message#dns_message{ra = false}, AuthorityRecords, Question#dns_query.name, Question#dns_query.type, Host).

resolve(Message, AuthorityRecords, Qname, Qtype, Host) ->
  % Step 2: Search the available zones for the zone which is the nearest ancestor to QNAME
  Zone = erldns_metrics:measure(none, ?MODULE, find_zone, [Qname, lists:last(AuthorityRecords)]), % Zone lookup
  Records = erldns_metrics:measure(none, ?MODULE, resolve, [Message, Qname, Qtype, Zone, Host, []]),
  RewrittenRecords = rewrite_soa_ttl(Records),
  erldns_metrics:measure(none, ?MODULE, additional_processing, [RewrittenRecords, Host, Zone]).

resolve(Message, _Qname, _Qtype, {error, not_authoritative}, _Host, _CnameChain) ->
  {Authority, Additional} = erldns_records:root_hints(),
  Message#dns_message{aa = true, rc = ?DNS_RCODE_NOERROR, authority = Authority, additional = Additional};
resolve(Message, Qname, Qtype, Zone, Host, CnameChain) ->
  % Step 3: Match records
  resolve(Message, Qname, Qtype, find_records_by_name(Qname, Zone), Host, CnameChain, Zone). % Query Zone for name

%% There were no exact matches on name, so move to the best-match resolution.
resolve(Message, Qname, Qtype, [], Host, CnameChain, Zone) ->
  best_match_resolution(Message, Qname, Qtype, Host, CnameChain, best_match(Qname, Zone), Zone); % Query Zone for best match name
%% There was at least one exact match on name.
resolve(Message, Qname, Qtype, MatchedRecords, Host, CnameChain, Zone) ->
  lager:debug("Exect match on name ~p (records: ~p)", [Qname, MatchedRecords]),
  exact_match_resolution(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone).

%% Determine if there is a CNAME anywhere in the records with the given Qname.
exact_match_resolution(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone) ->
  CnameRecords = lists:filter(match_type(?DNS_TYPE_CNAME), MatchedRecords), % Query record set for CNAME type
  exact_match_resolution(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone, CnameRecords).
%% No CNAME records found in the records with the Qname
exact_match_resolution(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone, []) ->
  resolve_exact_match(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone);
%% CNAME records found in the records for the Qname
exact_match_resolution(Message, _Qname, Qtype, Host, CnameChain, MatchedRecords, Zone, CnameRecords) ->
  resolve_exact_match_with_cname(Message, Qtype, Host, CnameChain, MatchedRecords, Zone, CnameRecords).

%% There were no CNAMEs found in the exact name matches, so now we grab the authority
%% records and find any type matches on QTYPE and continue on.
resolve_exact_match(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone) ->
  lager:debug("Resolving exact match on type ~p", [Qtype]),
  AuthorityRecords = lists:filter(match_type(?DNS_TYPE_SOA), MatchedRecords), % Query matched records for SOA type
  TypeMatches = lists:filter(match_type(Qtype), MatchedRecords), % Query matched records for Qtype
  case TypeMatches of
    [] ->
      %% Ask the custom handlers for their records.
      NewRecords = lists:flatten(lists:map(custom_lookup(Qname, Qtype, MatchedRecords), get_handlers())),
      resolve_exact_match(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone, NewRecords, AuthorityRecords);
    _ ->
      resolve_exact_match(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone, TypeMatches, AuthorityRecords)
  end.

%% There were no matches for exact name and type, so now we are looking for NS records
%% in the exact name matches.
resolve_exact_match(Message, _Qname, Qtype, Host, CnameChain, MatchedRecords, Zone, [], AuthorityRecords) ->
  ReferralRecords = lists:filter(match_type(?DNS_TYPE_NS), MatchedRecords), % Query matched records for NS type
  resolve_no_exact_type_match(Message, Qtype, Host, CnameChain, [], Zone, MatchedRecords, ReferralRecords, AuthorityRecords);
%% There were exact matches of name and type.
resolve_exact_match(Message, _Qname, Qtype, Host, CnameChain, _MatchedRecords, Zone, ExactTypeMatches, AuthorityRecords) ->
  resolve_exact_type_match(Message, Qtype, Host, CnameChain, ExactTypeMatches, Zone, AuthorityRecords).

resolve_exact_type_match(Message, ?DNS_TYPE_NS, Host, CnameChain, MatchedRecords, Zone, []) ->
  Answer = lists:last(MatchedRecords),
  Name = Answer#dns_rr.name,
  lager:debug("Restarting query with delegated name ~p", [Name]),
  % It isn't clear what the QTYPE should be on a delegated restart. I assume an A record.
  restart_delegated_query(Message, Name, ?DNS_TYPE_A, Host, CnameChain, Zone, in_zone(Name, Zone));

resolve_exact_type_match(Message, ?DNS_TYPE_NS, _Host, _CnameChain, MatchedRecords, _Zone, _AuthorityRecords) ->
  lager:debug("Authoritative for record, returning answers"),
  Message#dns_message{aa = true, rc = ?DNS_RCODE_NOERROR, answers = Message#dns_message.answers ++ MatchedRecords};
resolve_exact_type_match(Message, Qtype, Host, CnameChain, MatchedRecords, Zone, _AuthorityRecords) ->
  Answer = lists:last(MatchedRecords),
  NSRecords = delegation_records(Answer#dns_rr.name, Zone), % NS lookup
  resolve_exact_type_match(Message, Qtype, Host, CnameChain, MatchedRecords, Zone, _AuthorityRecords, NSRecords).

resolve_exact_type_match(Message, _Qtype, _Host, _CnameChain, MatchedRecords, _Zone, _AuthorityRecords, []) ->
  lager:debug("Returning authoritative answer with ~p appended answers", [length(MatchedRecords)]),
  Message#dns_message{aa = true, rc = ?DNS_RCODE_NOERROR, answers = Message#dns_message.answers ++ MatchedRecords};
resolve_exact_type_match(Message, Qtype, Host, CnameChain, MatchedRecords, Zone, _AuthorityRecords, NSRecords) ->
  Answer = lists:last(MatchedRecords),
  NSRecord = lists:last(NSRecords),
  Name = NSRecord#dns_rr.name,
  case Name =:= Answer#dns_rr.name of
    true ->
      lager:debug("Name matches an existing answer name so this is an authority"),
      Message#dns_message{aa = false, rc = ?DNS_RCODE_NOERROR, authority = Message#dns_message.authority ++ NSRecords};
    false ->
      lager:debug("Restarting query with delegated name ~p", [Name]),
      restart_delegated_query(Message, Name, Qtype, Host, CnameChain, Zone, in_zone(Name, Zone))
  end.

restart_delegated_query(Message, Name, Qtype, Host, CnameChain, Zone, true) ->
  resolve(Message, Name, Qtype, Zone, Host, CnameChain);
restart_delegated_query(Message, Name, Qtype, Host, CnameChain, Zone, false) ->
  resolve(Message, Name, Qtype, find_zone(Name, Zone#zone.authority), Host, CnameChain). % Zone lookup

%% There were no exact type matches, but there were other name matches and there are NS records.
%% Since the Qtype is ANY we indicate we are authoritative and include the NS records.
resolve_no_exact_type_match(Message, ?DNS_TYPE_ANY, _Host, _CnameChain, _ExactTypeMatches, _Zone, [], [], AuthorityRecords) ->
  Message#dns_message{aa = true, authority = AuthorityRecords};
resolve_no_exact_type_match(Message, _Qtype, _Host, _CnameChain, [], Zone, _MatchedRecords, [], _AuthorityRecords) ->
  Message#dns_message{aa = true, authority = Zone#zone.authority};
resolve_no_exact_type_match(Message, _Qtype, _Host, _CnameChain, ExactTypeMatches, _Zone, _MatchedRecords, [], _AuthorityRecords) ->
  Message#dns_message{aa = true, answers = Message#dns_message.answers ++ ExactTypeMatches};
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
% the answers section..
resolve_exact_match_with_cname(Message, ?DNS_TYPE_CNAME, _Host, _CnameChain, _MatchedRecords, _Zone, CnameRecords) ->
  Message#dns_message{aa = true, answers = Message#dns_message.answers ++ CnameRecords};
% There is a CNAME record, however the Qtype is not CNAME, check for a CNAME loop before continuing.
resolve_exact_match_with_cname(Message, Qtype, Host, CnameChain, MatchedRecords, Zone, CnameRecords) ->
  resolve_exact_match_with_cname(Message, Qtype, Host, CnameChain, MatchedRecords, Zone, CnameRecords, lists:member(lists:last(CnameRecords), CnameChain)).

%% Indicates a CNAME loop. The response code is a SERVFAIL in this case.
resolve_exact_match_with_cname(Message, _Qtype, _Host, _CnameChain, _MatchedRecords, _Zone, _CnameRecords, true) ->
  lager:debug("CNAME loop detected (exact match)"),
  Message#dns_message{aa = true, rc = ?DNS_RCODE_SERVFAIL};
% No CNAME loop, restart the query with the CNAME content.
resolve_exact_match_with_cname(Message, Qtype, Host, CnameChain, _MatchedRecords, Zone, CnameRecords, false) ->
  CnameRecord = lists:last(CnameRecords),
  Name = CnameRecord#dns_rr.data#dns_rrdata_cname.dname,
  lager:debug("Restarting query with CNAME name ~p (exact match)", [Name]),
  restart_query(Message#dns_message{aa = true, answers = Message#dns_message.answers ++ CnameRecords}, Name, Qtype, Host, CnameChain ++ CnameRecords, Zone, in_zone(Name, Zone)).

% The CNAME is in the zone so we do not need to look it up again.
restart_query(Message, Name, Qtype, Host, CnameChain, Zone, true) ->
  resolve(Message, Name, Qtype, Zone, Host, CnameChain);
% The CNAME is not in the zone, so we need to find the zone using the
% CNAME content.
restart_query(Message, Name, Qtype, Host, CnameChain, _Zone, false) ->
  resolve(Message, Name, Qtype, find_zone(Name), Host, CnameChain).

% There was no exact match for the Qname, so we use the best matches that were
% returned by the best_match() function.
best_match_resolution(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone) ->
  lager:debug("No exact match found, using ~p", [BestMatchRecords]),
  ReferralRecords = lists:filter(match_type(?DNS_TYPE_NS), BestMatchRecords), % NS lookup
  best_match_resolution(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, ReferralRecords).

% There were no NS records in the best matches.
best_match_resolution(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, []) ->
  resolve_best_match(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone);
% There were NS records in the best matches, so this is a referral.
best_match_resolution(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, ReferralRecords) ->
  resolve_best_match_referral(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, ReferralRecords).

resolve_best_match(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone) ->
  lager:debug("No referrals found"),
  resolve_best_match(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, lists:any(match_wildcard(), BestMatchRecords)).

%% It's a wildcard match
resolve_best_match(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, true) ->
  lager:debug("Matched records are wildcard."),
  CnameRecords = lists:filter(match_type(?DNS_TYPE_CNAME), lists:map(replace_name(Qname), BestMatchRecords)),
  resolve_best_match_with_wildcard(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, CnameRecords);
resolve_best_match(Message, Qname, _Qtype, _Host, _CnameChain, _BestMatchRecords, Zone, false) ->
  lager:debug("Matched records are not wildcard."),
  [Question|_] = Message#dns_message.questions,
  resolve_best_match_not_wildcard(Message, Zone, Qname =:= Question#dns_query.name).

resolve_best_match_not_wildcard(Message, _Zone, false) ->
  lager:debug("Qname did not match query name"),
  {Authority, Additional} = erldns_records:root_hints(),
  Message#dns_message{authority=Authority, additional=Additional};
resolve_best_match_not_wildcard(Message, Zone, true) ->
  lager:debug("Qname matched query name"),
  Message#dns_message{rc = ?DNS_RCODE_NXDOMAIN, authority = Zone#zone.authority, aa = true}.

% It's not a wildcard CNAME
resolve_best_match_with_wildcard(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone, []) ->
  lager:debug("Wildcard is not CNAME"),
  TypeMatchedRecords = case Qtype of
    ?DNS_TYPE_ANY -> MatchedRecords;
    _ -> lists:filter(match_type(Qtype), MatchedRecords)
  end,
  TypeMatches = lists:map(replace_name(Qname), TypeMatchedRecords),
  case TypeMatches of
    [] ->
      %% Ask the custom handlers for their records.
      NewRecords = lists:map(replace_name(Qname), lists:flatten(lists:map(custom_lookup(Qname, Qtype, MatchedRecords), get_handlers()))),
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
  lager:debug("CNAME loop detected (best match)"),
  Message#dns_message{aa = true, rc = ?DNS_RCODE_SERVFAIL};
% We should follow the CNAME
resolve_best_match_with_wildcard_cname(Message, _Qname, Qtype, Host, CnameChain, _BestMatchRecords, Zone, CnameRecords, false) ->
  lager:debug("Follow CNAME (best match)"),
  CnameRecord = lists:last(CnameRecords),
  Name = CnameRecord#dns_rr.data#dns_rrdata_cname.dname,
  restart_query(Message#dns_message{aa = true, answers = Message#dns_message.answers ++ CnameRecords}, Name, Qtype, Host, CnameChain ++ CnameRecords, Zone, in_zone(Name, Zone)).

% There are referral records
resolve_best_match_referral(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, ReferralRecords) ->
  resolve_best_match_referral(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, ReferralRecords, lists:filter(match_type(?DNS_TYPE_SOA), BestMatchRecords)). % Lookup SOA in best match records

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

%% See if additional processing is necessary.
additional_processing(Message, _Host, {error, _}) ->
  Message;
additional_processing(Message, Host, Zone) ->
  RequiresAdditionalProcessing = requires_additional_processing(Message#dns_message.answers ++ Message#dns_message.authority, []),
  erldns_metrics:measure(none, ?MODULE, additional_processing, [Message, Host, Zone, lists:flatten(RequiresAdditionalProcessing)]).
%% No records require additional processing.
additional_processing(Message, _Host, _Zone, []) ->
  Message;
%% There are records with names that require additional processing.
additional_processing(Message, Host, Zone, Names) ->
  RRs = lists:flatten(lists:map(fun(Name) -> find_records_by_name(Name, Zone) end, Names)),
  Records = lists:filter(match_type(?DNS_TYPE_A), RRs),
  additional_processing(Message, Host, Zone, Names, Records).

%% No additional A records were found, so just return the message.
additional_processing(Message, _Host, _Zone, _Names, []) ->
  Message;
%% Additional A records were found, so we add them to the additional section.
additional_processing(Message, _Host, _Zone, _Names, Records) ->
  Message#dns_message{additional=Message#dns_message.additional ++ Records}.

%% Given a list of answers find the names that require additional processing.
requires_additional_processing([], RequiresAdditional) -> RequiresAdditional;
requires_additional_processing([Answer|Rest], RequiresAdditional) ->
  Names = case Answer#dns_rr.data of
    Data when is_record(Data, dns_rrdata_ns) -> [Data#dns_rrdata_ns.dname];
    Data when is_record(Data, dns_rrdata_mx) -> [Data#dns_rrdata_mx.exchange];
    _ -> []
  end,
  requires_additional_processing(Rest, RequiresAdditional ++ Names).

%% Get the SOA authority for the current query.
get_authority(MessageOrName) ->
  case erldns_zone_cache:get_authority(MessageOrName) of
    {ok, Authority} -> [Authority];
    {error, _} -> []
  end.

%% Return true if the name is in the zone.
in_zone(Name, _Zone) -> erldns_zone_cache:in_zone(Name).

%% Find the zone for the given name.
find_zone(Qname) -> erldns_zone_cache:find_zone(Qname).
find_zone(Qname, Authority) -> erldns_zone_cache:find_zone(Qname, Authority).

%% Find the records for the given name in the given zone.
find_records_by_name(Name, _Zone) -> erldns_zone_cache:get_records_by_name(Name).

%% Various matching functions.
match_type(Type) -> fun(R) when is_record(R, dns_rr) -> R#dns_rr.type =:= Type end.
match_wildcard() -> fun(R) when is_record(R, dns_rr) -> lists:any(fun(L) -> L =:= <<"*">> end, dns:dname_to_labels(R#dns_rr.name)) end.

%% Function for executing custom lookups by registered handlers.
custom_lookup(Qname, Qtype, Records) ->
  fun({Module, Types}) ->
      case lists:member(Qtype, Types) of
        true -> Module:handle(Qname, Qtype, Records);
        false -> []
      end
  end.

%% Replacement functions.
replace_name(Name) -> fun(R) when is_record(R, dns_rr) -> R#dns_rr{name = Name} end.

%% Find all delegation records for the given Name in the provided
%% Records. This function may return an empty list, which means
%% the record is not a glue record.
delegation_records(Name, _Zone) -> erldns_zone_cache:get_delegations(Name).

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
rewrite_soa_ttl(Message, [R|Rest], NewAuthority) -> rewrite_soa_ttl(Message, Rest, NewAuthority ++ [minimum_soa_ttl(R, R#dns_rr.data)]).

minimum_soa_ttl(Record, Data) when is_record(Data, dns_rrdata_soa) -> Record#dns_rr{ttl = erlang:min(Data#dns_rrdata_soa.minimum, Record#dns_rr.ttl)};
minimum_soa_ttl(Record, _) -> Record.
