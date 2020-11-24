%% Copyright (c) 2012-2020, DNSimple Corporation
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

-include_lib("dns_erlang/include/dns.hrl").

-include("erldns.hrl").

-export([resolve/3]).

-ifdef(TEST).

-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").

-endif.

%% @doc Resolve the first question in the message. If no message is present, return the original
%% message. If multiple questions are present, only resolve the first question.
-spec resolve(Message :: dns:message(), AuthorityRecords :: [dns:rr()], Host :: dns:ip()) -> dns:message().
resolve(Message, AuthorityRecords, Host) ->
    case Message#dns_message.questions of
        [] ->
            Message;
        [Question] ->
            resolve_question(Message, AuthorityRecords, Host, Question);
        [Question | _] ->
            resolve_question(Message, AuthorityRecords, Host, Question)
    end.

-ifdef(TEST).

resolve_no_question_returns_message_test() ->
    Q = #dns_message{questions = []},
    ?assertEqual(Q, resolve(Q, [], {1, 1, 1, 1})).

-endif.

%% @doc Start the resolution process on the given question.
%% Step 1: Set the RA bit to false as we do not handle recursive queries.
-spec resolve_question(Message :: dns:message(), AuthorityRecords :: [dns:rr()], Host :: dns:ip(), Questions :: dns:questions() | dns:query()) ->
                          dns:message().
resolve_question(Message, AuthorityRecords, Host, Question) when is_record(Question, dns_query) ->
    case Question#dns_query.type of
        ?DNS_TYPE_RRSIG ->
            % Refuse all RRSIG requests.
            Message#dns_message{ra = false,
                                ad = false,
                                cd = false,
                                rc = ?DNS_RCODE_REFUSED};
        Qtype ->
            check_dnssec(Message, Host, Question),
            resolve_qname_and_qtype(Message#dns_message{ra = false,
                                                        ad = false,
                                                        cd = false},
                                    AuthorityRecords,
                                    Question#dns_query.name,
                                    Qtype,
                                    Host)
    end.

-ifdef(TEST).

resolve_rrsig_refused_test() ->
    Q = #dns_message{questions = [#dns_query{type = ?DNS_TYPE_RRSIG}]},
    A = resolve(Q, [], {1, 1, 1, 1}),
    ?assertEqual(?DNS_RCODE_REFUSED, A#dns_message.rc).

-endif.

%% @doc With the extracted Qname and Qtype in hand, find the nearest zone
%% Step 2: Search the available zones for the zone which is the nearest ancestor to QNAME
%%
%% If the request required DNSSEC, apply the DNSSEC records. Sort answers prior to returning.
-spec resolve_qname_and_qtype(Message :: dns:message(), [dns:rr()], dns:dname(), dns:type(), dns:ip()) -> dns:message().
resolve_qname_and_qtype(Message, AuthorityRecords, Qname, Qtype, Host) ->
    case AuthorityRecords of
        [] ->
            % Authority records is empty, refuse query
            Message#dns_message{rc = ?DNS_RCODE_REFUSED};
        _ ->
            % Authority records present, continue resolution
            Zone = erldns_zone_cache:find_zone(Qname, lists:last(AuthorityRecords)),
            ResolvedMessage = resolve_authoritative(Message, Qname, Qtype, Zone, Host, _CnameChain = []),
            sort_answers(erldns_dnssec:handle(additional_processing(erldns_records:rewrite_soa_ttl(ResolvedMessage), Host, Zone), Zone, Qname, Qtype))
    end.

-ifdef(TEST).

resolve_no_authority_refused_test() ->
    Q = #dns_message{questions = [#dns_query{type = Qtype = ?DNS_TYPE_A, name = Qname = <<"example.com">>}]},
    A = resolve_qname_and_qtype(Q, [], Qname, Qtype, {1, 1, 1, 1}),
    ?assertEqual(?DNS_RCODE_REFUSED, A#dns_message.rc).

-endif.

%% An SOA was found, thus we are authoritative and have the zone.
%%
%% Step 3: Match records
-spec resolve_authoritative(Message :: dns:message(),
                            Qname :: dns:dname(),
                            Qtype :: dns:type(),
                            Zone :: #zone{},
                            Host :: dns:ip(),
                            CnameChain :: [dns:rr()]) ->
                               dns:message().
resolve_authoritative(Message, Qname, Qtype, Zone, Host, CnameChain) ->
    Result =
        case {erldns_zone_cache:record_name_in_zone(Zone#zone.name, Qname), CnameChain} of
            {false, []} ->
                % No host name with the given record in the zone, return NXDOMAIN and include authority
                Message#dns_message{aa = true,
                                    rc = ?DNS_RCODE_NXDOMAIN,
                                    authority = Zone#zone.authority};
            _ ->
                case erldns_zone_cache:get_records_by_name(Qname) of
                    [] ->
                        % No exact match of name and type, move to best match resolution
                        best_match_resolution(Message, Qname, Qtype, Host, CnameChain, best_match(Qname, Zone), Zone);
                    Records ->
                        % Exact match of name and type
                        exact_match_resolution(Message, Qname, Qtype, Host, CnameChain, Records, Zone)
                end
        end,

    case detect_zonecut(Zone, Qname) of
        [] ->
            Result;
        ZonecutRecords ->
            CnameAnswers = lists:filter(erldns_records:match_type(?DNS_TYPE_CNAME), Result#dns_message.answers),
            FilteredCnameAnswers =
                lists:filter(fun(RR) ->
                                case detect_zonecut(Zone, RR#dns_rr.data#dns_rrdata_cname.dname) of
                                    [] -> false;
                                    _ -> true
                                end
                             end,
                             CnameAnswers),
            Message#dns_message{aa = false,
                                rc = ?DNS_RCODE_NOERROR,
                                authority = ZonecutRecords,
                                answers = FilteredCnameAnswers}
    end.

-ifdef(TEST).

resolve_authoritative_host_not_found_test() ->
    erldns_zone_cache:start_link(),
    Qname = <<"example.com">>,
    Z = #zone{name = <<"example.com">>, authority = Authority = [#dns_rr{name = <<"example.com">>, type = ?DNS_TYPE_SOA}]},
    Q = #dns_message{questions = [#dns_query{name = Qname, type = Qtype = ?DNS_TYPE_A}]},
    A = resolve_authoritative(Q, Qname, Qtype, Z, {}, _CnameChain = []),
    ?assertEqual(true, A#dns_message.aa),
    ?assertEqual(?DNS_RCODE_NXDOMAIN, A#dns_message.rc),
    ?assertEqual(Authority, A#dns_message.authority).

resolve_authoritative_zone_cut_test() ->
    erldns_zone_cache:start_link(),
    erldns_handler:start_link(),
    Qname = <<"delegated.example.com">>,
    NsRecords = [#dns_rr{name = Qname, type = ?DNS_TYPE_NS}],
    Z = #zone{name = ZoneName = <<"example.com">>, authority = Authority = [#dns_rr{name = <<"example.com">>, type = ?DNS_TYPE_SOA}]},
    Q = #dns_message{questions = [#dns_query{name = Qname, type = Qtype = ?DNS_TYPE_A}]},
    erldns_zone_cache:put_zone({ZoneName, <<"_">>, Authority ++ NsRecords}),
    A = resolve_authoritative(Q, Qname, Qtype, Z, {}, []),
    ?assertEqual(false, A#dns_message.aa),
    ?assertEqual(?DNS_RCODE_NOERROR, A#dns_message.rc),
    ?assertEqual(NsRecords, A#dns_message.authority),
    ?assertEqual([], A#dns_message.answers),
    erldns_zone_cache:delete_zone(ZoneName).

resolve_authoritative_zone_cut_with_cnames_test() ->
    erldns_zone_cache:start_link(),
    erldns_handler:start_link(),
    Qname = <<"delegated.example.com">>,
    CnameRecords =
        [#dns_rr{name = Qname,
                 type = ?DNS_TYPE_CNAME,
                 data = #dns_rrdata_cname{dname = <<"delegated-ns.example.com">>}}],
    NsRecords = [#dns_rr{name = <<"delegated-ns.example.com">>, type = ?DNS_TYPE_NS}],
    Z = #zone{name = ZoneName = <<"example.com">>, authority = Authority = [#dns_rr{name = <<"example.com">>, type = ?DNS_TYPE_SOA}]},
    Q = #dns_message{questions = [#dns_query{name = Qname, type = Qtype = ?DNS_TYPE_A}]},
    erldns_zone_cache:put_zone({ZoneName, <<"_">>, Authority ++ NsRecords ++ CnameRecords}),
    A = resolve_authoritative(Q, Qname, Qtype, Z, {}, _CnameChain = []),
    ?assertEqual(false, A#dns_message.aa),
    ?assertEqual(?DNS_RCODE_NOERROR, A#dns_message.rc),
    ?assertEqual(NsRecords, A#dns_message.authority),
    ?assertEqual(CnameRecords, A#dns_message.answers),
    erldns_zone_cache:delete_zone(ZoneName).

-endif.

%% Determine if there is a CNAME anywhere in the records with the given Qname.
exact_match_resolution(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone) ->
    case lists:filter(erldns_records:match_type(?DNS_TYPE_CNAME), MatchedRecords) of
        [] ->
            % No CNAME records found in the record set for the Qname
            resolve_exact_match(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone);
        CnameRecords ->
            % CNAME records found in the record set for the Qname
            resolve_exact_match_with_cname(Message, Qtype, Host, CnameChain, MatchedRecords, Zone, CnameRecords)
    end.

%% There were no CNAMEs found in the exact name matches, so now we grab the authority
%% records and find any type matches on QTYPE and continue on.
%%
%% This function will search both MatchedRecords and custom handlers.
-spec resolve_exact_match(Message :: dns:message(),
                          Qname :: dns:dname(),
                          Qtype :: dns:type(),
                          Host :: dns:ip(),
                          CnameChain :: [dns:rr()],
                          MatchedRecords :: [dns:rr()],
                          Zone :: #zone{}) ->
                             dns:message().
resolve_exact_match(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone) ->
    TypeMatches =
        case Qtype of
            ?DNS_TYPE_ANY ->
                filter_records(MatchedRecords, erldns_handler:get_versioned_handlers());
            _ ->
                lists:filter(erldns_records:match_type(Qtype), MatchedRecords)
        end,
    ExactTypeMatches =
        case TypeMatches of
            [] ->
                % No records matched the qtype, call custom handler
                Handlers = erldns_handler:get_versioned_handlers(),
                HandlerRecords = lists:flatten(lists:map(call_handlers(Qname, Qtype, MatchedRecords, Message), Handlers)),
                erldns_dnssec:maybe_sign_rrset(Message, HandlerRecords, Zone);
            _ ->
                % Records match qtype, use them
                TypeMatches
        end,
    AuthorityRecords = lists:filter(erldns_records:match_type(?DNS_TYPE_SOA), MatchedRecords),
    ReferralRecords = lists:filter(erldns_records:match_type(?DNS_TYPE_NS), MatchedRecords),
    case {ExactTypeMatches, ReferralRecords} of
        {[], []} ->
            % There are no exact type matches and no referrals, return NOERROR with the authority set
            Message#dns_message{aa = true, authority = Zone#zone.authority};
        {[], _} ->
            % There were no exact type matches, but there were other name matches and there are NS records, so this is an exact match referral
            resolve_exact_match_referral(Message, Qtype, MatchedRecords, ReferralRecords, AuthorityRecords);
        _ ->
            % There were exact matches of name and type.
            resolve_exact_type_match(Message, Qname, Qtype, Host, CnameChain, ExactTypeMatches, Zone, AuthorityRecords)
    end.

-spec resolve_exact_type_match(Message :: dns:message(),
                               Qname :: dns:dname(),
                               Qtype :: dns:type(),
                               Host :: dns:ip(),
                               CnameChain :: [dns:rr()],
                               MatchedRecords :: [dns:rr()],
                               Zone :: #zone{},
                               AuthorityRecords :: [dns:rr()]) ->
                                  dns:message().
resolve_exact_type_match(Message, Qname, ?DNS_TYPE_NS, Host, CnameChain, MatchedRecords, Zone, []) ->
    % There was an exact type match for an NS query, however there is no SOA record for the zone.
    lager:info("Exact match for NS with no SOA in the zone (qname: ~p)", [Qname]),
    Answer = lists:last(MatchedRecords),
    Name = Answer#dns_rr.name,
    % It isn't clear what the QTYPE should be on a delegated restart. I assume an A record.
    restart_delegated_query(Message, Name, ?DNS_TYPE_A, Host, CnameChain, Zone, erldns_zone_cache:in_zone(Name));
resolve_exact_type_match(Message, _Qname, ?DNS_TYPE_NS, _Host, _CnameChain, MatchedRecords, _Zone, _AuthorityRecords) ->
    % There was an exact type match for an NS query and an SOA record.
    Message#dns_message{aa = true,
                        rc = ?DNS_RCODE_NOERROR,
                        answers = Message#dns_message.answers ++ MatchedRecords};
resolve_exact_type_match(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone, AuthorityRecords) ->
    % There was an exact type match for something other than an NS record and we are authoritative because there is an SOA record.
    Answer = lists:last(MatchedRecords),
    case erldns_zone_cache:get_delegations(Answer#dns_rr.name) of
        [] ->
            % We are authoritative and there are no NS records here.
            Message#dns_message{aa = true,
                                rc = ?DNS_RCODE_NOERROR,
                                answers = Message#dns_message.answers ++ MatchedRecords};
        NSRecords ->
            % NOTE: this is a potential bug because it assumes the last record is the one to examine.
            NSRecord = lists:last(NSRecords),
            SoaRecord = lists:last(Zone#zone.authority),
            case SoaRecord#dns_rr.name =:= NSRecord#dns_rr.name of
                true ->
                    % The SOA record name matches the NS record name, we are at the apex, NOERROR and append the matched records to the answers
                    Message#dns_message{aa = true,
                                        rc = ?DNS_RCODE_NOERROR,
                                        answers = Message#dns_message.answers ++ MatchedRecords};
                false ->
                    % The SOA record and NS name do not match, so this may require restarting the search as the name may or may not be
                    % delegated to another zone in the cache
                    resolve_exact_type_match_delegated(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone, AuthorityRecords, NSRecords)
            end
    end.

%% @doc There is an exact name and type match and there NS records present. This may indicate the name is at the apex
%% or it may indicate that the name is delegated.
-spec resolve_exact_type_match_delegated(Message :: dns:message(),
                                         Qname :: dns:dname(),
                                         Qtype :: dns:type(),
                                         Host :: dns:ip(),
                                         CnameChain :: [dns:rr()],
                                         MatchedRecords :: [dns:rr()],
                                         Zone :: #zone{},
                                         AuthorityRecords :: [dns:rr()],
                                         NSRecords :: [dns:rr()]) ->
                                            dns:message().
resolve_exact_type_match_delegated(Message, _Qname, Qtype, Host, CnameChain, MatchedRecords, Zone, _AuthorityRecords, NSRecords) ->
    % We are authoritative and there are NS records here.
    % NOTE: there are potential bugs here because it assumes the last record is the one to examine
    Answer = lists:last(MatchedRecords),
    NSRecord = lists:last(NSRecords),
    Name = NSRecord#dns_rr.name,
    case Name =:= Answer#dns_rr.name of
        true ->
            % NS name matches answer name, thus it's a recursion, so return the message
            Message#dns_message{aa = false,
                                rc = ?DNS_RCODE_NOERROR,
                                authority = Message#dns_message.authority ++ NSRecords};
        false ->
            % NS name is different than the name in the matched records
            case check_if_parent(Name, Answer#dns_rr.name) of
                true ->
                    % NS record name is a parent of the answer name
                    restart_delegated_query(Message, Name, Qtype, Host, CnameChain, Zone, erldns_zone_cache:in_zone(Name));
                false ->
                    % NS record name is not a parent of the answer name
                    Message#dns_message{aa = true,
                                        rc = ?DNS_RCODE_NOERROR,
                                        answers = Message#dns_message.answers ++ MatchedRecords,
                                        additional = Message#dns_message.additional}
            end
    end.

-spec resolve_exact_match_referral(Message :: dns:message(),
                                   Qtype :: dns:type(),
                                   MatchedRecords :: [dns:rr()],
                                   ReferralRecords :: [dns:rr()],
                                   AuthorityRecords :: [dns:rr()]) ->
                                      dns:message().
resolve_exact_match_referral(Message, _Qtype, _MatchedRecords, ReferralRecords, []) ->
    % Given an exact name match where the Qtype is not found in the record set and we are not authoritative,
    % add the NS records to the authority section of the message.
    Message#dns_message{authority = Message#dns_message.authority ++ ReferralRecords};
resolve_exact_match_referral(Message, ?DNS_TYPE_ANY, MatchedRecords, _ReferralRecords, _AuthorityRecords) ->
    % Given an exact name match and the type of ANY, return all of the matched records.
    Message#dns_message{aa = true, answers = MatchedRecords};
resolve_exact_match_referral(Message, ?DNS_TYPE_NS, _MatchedRecords, ReferralRecords, _AuthorityRecords) ->
    % Given an exact name match and the type NS, where the NS records are not found in record set
    % return the NS records in the answers section of the message.
    Message#dns_message{aa = true, answers = ReferralRecords};
resolve_exact_match_referral(Message, ?DNS_TYPE_SOA, _MatchedRecords, _ReferralRecords, AuthorityRecords) ->
    % Given an exact name match and the type SOA, where the SOA record is not found in the records set,
    % return the SOA records in the answers section of the message.
    Message#dns_message{aa = true, answers = AuthorityRecords};
resolve_exact_match_referral(Message, _, _MatchedRecords, _ReferralRecords, AuthorityRecords) ->
    % Given an exact name match where the Qtype is not found in the record set and is not ANY, SOA or NS,
    % return the SOA records for the zone in the authority section of the message and set the RC to NOERROR.
    Message#dns_message{aa = true,
                        rc = ?DNS_RCODE_NOERROR,
                        authority = AuthorityRecords}.

-spec resolve_exact_match_with_cname(Message :: dns:message(),
                                     Qtype :: ?DNS_TYPE_CNAME,
                                     Host :: dns:ip(),
                                     CnameChain :: [dns:rr()],
                                     MatchedRecords :: [dns:rr()],
                                     Zone :: #zone{},
                                     CnameRecords :: [dns:rr()]) ->
                                        dns:message().
resolve_exact_match_with_cname(Message, ?DNS_TYPE_CNAME, _Host, _CnameChain, _MatchedRecords, _Zone, CnameRecords) ->
    % There is a CNAME record and the request was for a CNAME record so append the CNAME records to the answers section.
    Message#dns_message{aa = true, answers = Message#dns_message.answers ++ CnameRecords};
resolve_exact_match_with_cname(Message, Qtype, Host, CnameChain, _MatchedRecords, Zone, CnameRecords) ->
    % There is a CNAME record, however the Qtype is not CNAME, check for a CNAME loop before continuing.
    case lists:member(lists:last(CnameRecords), CnameChain) of
        true ->
            % Indicates a CNAME loop. The response code is a SERVFAIL in this case.
            Message#dns_message{aa = true, rc = ?DNS_RCODE_SERVFAIL};
        false ->
            % No CNAME loop, restart the query with the CNAME content.
            CnameRecord = lists:last(CnameRecords),
            Name = CnameRecord#dns_rr.data#dns_rrdata_cname.dname,
            restart_query(Message#dns_message{aa = true, answers = Message#dns_message.answers ++ CnameRecords},
                          Name,
                          Qtype,
                          Host,
                          CnameChain ++ CnameRecords,
                          Zone,
                          erldns_zone_cache:in_zone(Name))
    end.

-spec best_match_resolution(Message :: dns:message(),
                            Qname :: dns:dname(),
                            Qtype :: dns:type(),
                            Host :: dns:ip(),
                            CnameChain :: [dns:rr()],
                            BestMatchRecords :: [dns:rr()],
                            Zone :: #zone{}) ->
                               dns:message().
best_match_resolution(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone) ->
    % There was no exact match for the Qname, so we use the best matches that were returned by the best_match() function.
    ReferralRecords = lists:filter(erldns_records:match_type(?DNS_TYPE_NS), BestMatchRecords),
    case ReferralRecords of
        [] ->
            % There were no NS records in the best matches.
            resolve_best_match(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone);
        _ ->
            % There were NS records in the best matches, so this is a referral.
            resolve_best_match_referral(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, ReferralRecords)
    end.

%% @doc There is no referral, so check to see if there is a wildcard.
%%
%% If there is a wildcard present, then the resolver needs to continue to handle various possible types.
%%
%% If there is no wildcard present and the qname matches the original question then return NXDOMAIN.
%%
%% If there is no wildcard present and the qname does not match the origina question then return NOERROR
%% and include root hints in the additional section if necessary.
-spec resolve_best_match(Message :: dns:message(),
                         Qname :: dns:dname(),
                         Qtype :: dns:type(),
                         Host :: dns:ip(),
                         CnameChain :: [dns:rr()],
                         BestMatchRecords :: [dns:rr()],
                         Zone :: #zone{}) ->
                            dns:message().
resolve_best_match(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone) ->
    case lists:any(erldns_records:match_wildcard(), BestMatchRecords) of
        true ->
            % It's a wildcard match
            CnameRecords = lists:filter(erldns_records:match_type(?DNS_TYPE_CNAME), lists:map(erldns_records:replace_name(Qname), BestMatchRecords)),
            resolve_best_match_with_wildcard(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, CnameRecords);
        false ->
            % It's not a wildcard
            [Question | _] = Message#dns_message.questions,
            case Qname =:= Question#dns_query.name % TODO this logic can be moved up higher in processing potentially.
            of
                true ->
                    % We are authoritative but there is no match on name and type, so respond with NXDOMAIN
                    Message#dns_message{rc = ?DNS_RCODE_NXDOMAIN,
                                        authority = Zone#zone.authority,
                                        aa = true};
                false ->
                    % This happens when we have a CNAME to an out-of-balliwick hostname and the query is for
                    % something other than CNAME. Note that the response is still NOERROR here.
                    %
                    % In the dnstest suite, this is hit by cname_to_unauth_any (and others)
                    optionally_add_root_hints(Message)
            end
    end.

-spec resolve_best_match_with_wildcard(Message :: dns:message(),
                                       Qname :: dns:dname(),
                                       Qtype :: dns:type(),
                                       Host :: dns:ip(),
                                       CnameChain :: [dns:rr()],
                                       BestMatchRecords :: [dns:rr()],
                                       Zone :: #zone{},
                                       CnameRecords :: [dns:rr()]) ->
                                          dns:message().
resolve_best_match_with_wildcard(Message, Qname, Qtype, _Host, _CnameChain, MatchedRecords, Zone, []) ->
    % Handle best match resolving with a wildcard name in the zone.
    TypeMatchedRecords =
        case Qtype of
            ?DNS_TYPE_ANY ->
                filter_records(MatchedRecords, erldns_handler:get_versioned_handlers());
            _ ->
                lists:filter(erldns_records:match_type(Qtype), MatchedRecords)
        end,
    TypeMatches = lists:map(erldns_records:replace_name(Qname), TypeMatchedRecords),
    case TypeMatches of
        [] ->
            % There is no exact type matches for the original qtype, ask the custom handlers for their records.
            Handlers = erldns_handler:get_versioned_handlers(),
            HandlerRecords = lists:flatten(lists:map(call_handlers(Qname, Qtype, MatchedRecords, Message), Handlers)),
            Records = lists:map(erldns_records:replace_name(Qname), HandlerRecords),
            NewRecords = erldns_dnssec:maybe_sign_rrset(Message, Records, Zone),
            case NewRecords of
                [] ->
                    % Custom handlers returned no answers, so set the authority section of the response and return NOERROR
                    Message#dns_message{aa = true, authority = Zone#zone.authority};
                NewRecords ->
                    % Custom handlers returned answers
                    Message#dns_message{aa = true, answers = Message#dns_message.answers ++ NewRecords}
            end;
        _ ->
            % There is an exact type match
            Message#dns_message{aa = true, answers = Message#dns_message.answers ++ TypeMatches}
    end;
resolve_best_match_with_wildcard(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, CnameRecords) ->
    % It is a wildcard CNAME
    resolve_best_match_with_wildcard_cname(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, CnameRecords).

% Handle the case where the wildcard is a CNAME in the zone. If the Qtype was CNAME then answer, otherwise determine if
% the CNAME should be followed
-spec resolve_best_match_with_wildcard_cname(Message :: dns:message(),
                                             Qname :: dns:dname(),
                                             Qtype :: dns:type(),
                                             Host :: dns:ip(),
                                             CnameChain :: [dns:rr()],
                                             BestMatchRecords :: [dns:rr()],
                                             Zone :: #zone{},
                                             CnameRecords :: [dns:rr()]) ->
                                                dns:message().
resolve_best_match_with_wildcard_cname(Message, _Qname, ?DNS_TYPE_CNAME, _Host, _CnameChain, _BestMatchRecords, _Zone, CnameRecords) ->
    Message#dns_message{aa = true, answers = Message#dns_message.answers ++ CnameRecords};
resolve_best_match_with_wildcard_cname(Message, _Qname, Qtype, Host, CnameChain, _BestMatchRecords, Zone, CnameRecords) ->
    CnameRecord = lists:last(CnameRecords), % There should only be one CNAME. Multiple CNAMEs kill unicorns.
    case lists:member(CnameRecord, CnameChain) of
        true ->
            % Indicates CNAME loop
            Message#dns_message{aa = true, rc = ?DNS_RCODE_SERVFAIL};
        false ->
            % Follow the CNAME
            CnameRecord = lists:last(CnameRecords),
            Name = CnameRecord#dns_rr.data#dns_rrdata_cname.dname,
            UpdatedMessage = Message#dns_message{aa = true, answers = Message#dns_message.answers ++ CnameRecords},
            restart_query(UpdatedMessage, Name, Qtype, Host, CnameChain ++ CnameRecords, Zone, erldns_zone_cache:in_zone(Name))
    end.

% There are referral records
-spec resolve_best_match_referral(Message :: dns:message(),
                                  Qname :: dns:dname(),
                                  Qtype :: dns:type(),
                                  Host :: dns:ip(),
                                  CnameChain :: [dns:rr()],
                                  BestMatchRecords :: [dns:rr()],
                                  Zone :: #zone{},
                                  CnameRecords :: [dns:rr()]) ->
                                     dns:message().
resolve_best_match_referral(Message, _Qname, Qtype, _Host, CnameChain, BestMatchRecords, _Zone, ReferralRecords) ->
    Authority = lists:filter(erldns_records:match_type(?DNS_TYPE_SOA), BestMatchRecords),
    case {Qtype, Authority, CnameChain} of
        {_, [], []} ->
            % We are authoritative for the name since there was an SOA record in the best match results.
            Message#dns_message{aa = true,
                                rc = ?DNS_RCODE_NXDOMAIN,
                                authority = Authority};
        {_, _, []} ->
            % Indicate that we are not authoritative for the name as there were novSOA records in the best-match results.
            % The name has thus been delegated to another authority.
            Message#dns_message{aa = false, authority = Message#dns_message.authority ++ ReferralRecords};
        {?DNS_TYPE_ANY, _, _} ->
            % We are authoritative and the Qtype is ANY, return the original message
            Message;
        _ ->
            % We are authoritative and the Qtype is something other than ANY, set the authority in the response
            Message#dns_message{authority = Authority}
    end.

% The CNAME is in a zone. If it is the same zone, then continue the chain, otherwise return the message
-spec restart_query(Message :: dns:message(),
                    Name :: dns:dname(),
                    Qtype :: 0..255,
                    Host :: any(),
                    CnameChain :: any(),
                    Zone :: #zone{},
                    InZone :: boolean()) ->
                       dns:message().
restart_query(Message, Name, Qtype, Host, CnameChain, Zone, true) ->
    case check_if_parent(Zone#zone.name, Name) of
        true ->
            resolve_authoritative(Message, Name, Qtype, Zone, Host, CnameChain);
        false ->
            Message
    end;
% The CNAME is not in a zone, do not restart the query, return the answer.
restart_query(Message, _Name, _Qtype, _Host, _CnameChain, _Zone, false) ->
    Message.

-spec restart_delegated_query(Message :: dns:message(),
                              Qname :: dns:dname(),
                              Qtype :: dns:type(),
                              Host :: dns:ip(),
                              CnameChain :: [dns:rr()],
                              Zone :: #zone{},
                              InZone :: boolean()) ->
                                 dns:message().
% Delegated, but in the same zone.
restart_delegated_query(Message, Qname, Qtype, Host, CnameChain, Zone, true) ->
    resolve_authoritative(Message, Qname, Qtype, Zone, Host, CnameChain);
% Delegated to a different zone.
restart_delegated_query(Message, Qname, Qtype, Host, CnameChain, Zone, false) ->
    resolve_authoritative(Message, Qname, Qtype, erldns_zone_cache:find_zone(Qname, Zone#zone.authority), Host, CnameChain).

%% Utility functions

%% @doc If root hints are enabled, return an updated message with the root hints.
-spec optionally_add_root_hints(dns:message()) -> dns:message().
optionally_add_root_hints(Message) ->
    case erldns_config:use_root_hints() of
        true ->
            {Authority, Additional} = erldns_records:root_hints(),
            Message#dns_message{authority = Authority, additional = Message#dns_message.additional ++ Additional};
        _ ->
            Message
    end.

%% Returns true if the first domain name is a parent of the second domain name.
check_if_parent(PossibleParentName, Name) ->
    case lists:subtract(dns:dname_to_labels(PossibleParentName), dns:dname_to_labels(Name)) of
        [] ->
            true;
        _ ->
            false
    end.

% Find the best match records for the given Qname in the given zone. This will attempt to walk through the
% domain hierarchy in the Qname looking for both exact and wildcard matches.
-spec best_match(dns:dname(), #zone{}) -> [dns:rr()].
best_match(Qname, Zone) ->
    best_match(Qname, Zone, dns:dname_to_labels(Qname)).

-spec best_match(dns:dname(), #zone{}, [dns:label()]) -> [dns:rr()].
best_match(_Qname, _Zone, []) ->
    [];
best_match(Qname, Zone, [_ | Rest]) ->
    WildcardName = dns:labels_to_dname([<<"*">>] ++ Rest),
    best_match(Qname, Zone, Rest, erldns_zone_cache:get_records_by_name(WildcardName)).

-spec best_match(dns:dname(), #zone{}, [dns:label()], [dns:rr()]) -> [dns:rr()].
best_match(_Qname, _Zone, [], []) ->
    [];
best_match(Qname, Zone, Labels, []) ->
    Name = dns:labels_to_dname(Labels),
    case erldns_zone_cache:get_records_by_name(Name) of
        [] ->
            best_match(Qname, Zone, Labels);
        Matches ->
            Matches
    end;
best_match(_Qname, _Zone, _Labels, WildcardMatches) ->
    WildcardMatches.

%% Call all registered handlers.
-spec call_handlers(dns:dname(), dns:type(), [dns:rr()], dns:message()) -> fun(({module(), [dns:type()], integer()}) -> [dns:rr()]).
call_handlers(Qname, Qtype, Records, Message) ->
    fun({Module, Types, Version}) ->
       case Version of
           1 ->
               case lists:member(Qtype, Types) of
                   true -> Module:handle(Qname, Qtype, Records);
                   false ->
                       case Qtype =:= ?DNS_TYPE_ANY of
                           true -> Module:handle(Qname, Qtype, Records);
                           false -> []
                       end
               end;
           2 ->
               case lists:member(Qtype, Types) of
                   true -> Module:handle(Qname, Qtype, Records, Message);
                   false ->
                       case Qtype =:= ?DNS_TYPE_ANY of
                           true -> Module:handle(Qname, Qtype, Records, Message);
                           false -> []
                       end
               end
       end
    end.

% Filter records through registered handlers.
filter_records(Records, []) ->
    Records;
filter_records(Records, [{Handler, _Types, Version} | Rest]) ->
    case Version of
        1 ->
            filter_records(Handler:filter(Records), Rest);
        2 ->
            filter_records(Handler:filter(Records), Rest);
        _ ->
            []
    end.

%% See if additional processing is necessary.
additional_processing(Message, Host, Zone) ->
    RequiresAdditionalProcessing = requires_additional_processing(Message#dns_message.answers ++ Message#dns_message.authority, []),
    additional_processing(Message, Host, Zone, lists:flatten(RequiresAdditionalProcessing)).

%% No records require additional processing.
additional_processing(Message, _Host, _Zone, []) ->
    Message;
%% There are records with names that require additional processing.
additional_processing(Message, Host, Zone, Names) ->
    RRs = lists:flatten(lists:map(fun(Name) -> erldns_zone_cache:get_records_by_name(Name) end, Names)),
    Records = lists:filter(erldns_records:match_types([?DNS_TYPE_A, ?DNS_TYPE_AAAA]), RRs),
    additional_processing(Message, Host, Zone, Names, Records).

%% No additional A records were found, so just return the message.
additional_processing(Message, _Host, _Zone, _Names, []) ->
    Message;
%% Additional A records were found, so we add them to the additional section.
additional_processing(Message, _Host, _Zone, _Names, Records) ->
    Message#dns_message{additional = Message#dns_message.additional ++ Records}.

%% Given a list of answers find the names that require additional processing.
-spec requires_additional_processing(Records :: [dns:rr()], RecordsRequiringAdditionalProcessing :: [dns:rr()]) -> [dns:rr()].
requires_additional_processing([], RequiresAdditional) ->
    RequiresAdditional;
requires_additional_processing([Answer | Rest], RequiresAdditional) ->
    Names =
        case Answer#dns_rr.data of
            Data when is_record(Data, dns_rrdata_ns) ->
                [Data#dns_rrdata_ns.dname];
            Data when is_record(Data, dns_rrdata_mx) ->
                [Data#dns_rrdata_mx.exchange];
            _ ->
                []
        end,
    requires_additional_processing(Rest, RequiresAdditional ++ Names).

%% @doc Return true if DNSSEC is requested and enabled.
-spec check_dnssec(Message :: dns:message(), Host :: dns:ip(), Question :: dns:query()) -> boolean().
check_dnssec(Message, Host, Question) ->
    case proplists:get_bool(dnssec, erldns_edns:get_opts(Message)) of
        true ->
            erldns_events:notify({?MODULE, dnssec_request, Host, Question#dns_query.name}),
            true;
        false ->
            false
    end.

%% @doc Sort the answers in the given message.
-spec sort_answers(dns:message()) -> dns:message().
sort_answers(Message) ->
    Message#dns_message{answers = lists:usort(fun sort_fun/2, Message#dns_message.answers)}.

-spec sort_fun(dns:rr(), dns:rr()) -> boolean().
sort_fun(#dns_rr{type = ?DNS_TYPE_CNAME, data = #dns_rrdata_cname{dname = Name}}, #dns_rr{type = ?DNS_TYPE_CNAME, name = Name}) ->
    true;
sort_fun(#dns_rr{type = ?DNS_TYPE_CNAME, name = Name}, #dns_rr{type = ?DNS_TYPE_CNAME, data = #dns_rrdata_cname{dname = Name}}) ->
    false;
sort_fun(#dns_rr{type = ?DNS_TYPE_CNAME}, #dns_rr{}) ->
    true;
sort_fun(#dns_rr{}, #dns_rr{type = ?DNS_TYPE_CNAME}) ->
    false;
sort_fun(A, B) ->
    A =< B.

% Extract the name from the first record in the list.
zone_authority_name([Record | _]) ->
    Record#dns_rr.name.

% Find NS records that represent a zone cut.
detect_zonecut(Zone, Qname) when is_binary(Qname) ->
    detect_zonecut(Zone, dns:dname_to_labels(Qname));
detect_zonecut(_Zone, []) ->
    [];
detect_zonecut(_Zone, [_Label]) ->
    [];
detect_zonecut(Zone, [_ | ParentLabels] = Labels) ->
    Qname = dns:labels_to_dname(Labels),
    case dns:compare_dname(zone_authority_name(Zone#zone.authority), Qname) of
        true ->
            [];
        false ->
            case erldns_zone_cache:get_records_by_name_and_type(Qname, ?DNS_TYPE_NS) of
                [] ->
                    detect_zonecut(Zone, ParentLabels);
                ZonecutNSRecords ->
                    ZonecutNSRecords
            end
    end.
