-module(erldns_resolver).
-moduledoc """
Resolve a DNS query.

Assumes that the DNS message contains exactly one query.

## Telemetry events

### `[erldns, pipeline, resolver, error]`

Emitted when the resolver pipe catches an error: either a thrown `{error, rcode, RCODE}`
or an exception (mapped to SERVFAIL).

- **Measurements:** `#{count => 1}`
- **Metadata:** `#{rc => dns:rcode()}`
""".

-include_lib("dns_erlang/include/dns.hrl").
-include_lib("kernel/include/logger.hrl").
-include_lib("erldns/include/erldns.hrl").

-ifdef(TEST).
-export([resolve_authoritative/7]).
-endif.

-define(MAX_RESOLUTION_DEPTH, 32).

-behaviour(erldns_pipeline).

-export([prepare/1, call/2, deps/0]).

-define(LOG_METADATA, #{domain => [erldns, pipeline, resolver]}).

-doc "`c:erldns_pipeline:deps/0` callback.".
-spec deps() -> erldns_pipeline:deps().
deps() ->
    #{
        prerequisites => [erldns_questions],
        dependents => [erldns_sorter, erldns_section_counter]
    }.

-doc "`c:erldns_pipeline:prepare/1` callback.".
-spec prepare(erldns_pipeline:opts()) -> erldns_pipeline:opts().
prepare(Opts) ->
    Opts#{auth_zone => zone_not_found}.

-doc "`c:erldns_pipeline:call/2` callback.".
-spec call(dns:message(), erldns_pipeline:opts()) -> erldns_pipeline:return().
call(Msg, #{resolved := false, query_labels := QLabels, query_type := QType} = Opts) ->
    %% Search the available zones for the zone which is the nearest ancestor to QLabels
    case erldns_zone_cache:get_authoritative_zone(QLabels, QType) of
        #zone{} = Zone ->
            #dns_message{questions = [#dns_query{name = QName}]} = Msg,
            Msg1 = resolve(Msg, Zone, QLabels, QName, QType),
            Msg2 = complete_response(Msg1),
            {Msg2, Opts#{auth_zone => Zone, resolved => true}};
        Error when Error =:= not_authoritative; Error =:= zone_not_found ->
            Msg1 = Msg#dns_message{aa = false, rc = ?DNS_RCODE_REFUSED},
            Msg2 = optionally_add_root_hints(Msg1),
            complete_response(Msg2)
    end;
call(Msg, _) ->
    Msg.

%% Start the resolution process on the given question. Assumes only one question.
%% Handlers can escape the control flow by throwing `{error, rcode, RCODE}`.
-spec resolve(dns:message(), erldns:zone(), dns:labels(), dns:dname(), dns:type()) -> dns:message().
resolve(Msg, Zone, QLabels, QName, QType) ->
    try
        resolve_question(Msg, Zone, QLabels, QName, QType)
    catch
        throw:{error, rcode, RC} ->
            telemetry:execute([erldns, pipeline, resolver, error], #{count => 1}, #{rc => RC}),
            Msg#dns_message{aa = false, rc = RC};
        Class:Reason:Stacktrace ->
            ?LOG_ERROR(
                #{
                    what => resolve_error,
                    dns_message => Msg,
                    class => Class,
                    reason => Reason,
                    stacktrace => Stacktrace
                },
                ?LOG_METADATA
            ),
            telemetry:execute([erldns, pipeline, resolver, error], #{count => 1}, #{
                rc => ?DNS_RCODE_SERVFAIL
            }),
            Msg#dns_message{aa = false, rc = ?DNS_RCODE_SERVFAIL}
    end.

%% With the extracted QLabels and QType in hand,
-spec resolve_question(Msg, Zone, QLabels, QName, QType) -> Msg when
    Msg :: dns:message(),
    Zone :: erldns:zone(),
    QLabels :: dns:labels(),
    QName :: dns:dname(),
    QType :: dns:type().
resolve_question(Msg, Zone, QLabels, QName, QType) ->
    Msg1 = resolve_authoritative(Msg, Zone, QLabels, QName, QType, [], ?MAX_RESOLUTION_DEPTH),
    additional_processing(Msg1, Zone).

%% An SOA was found, thus we are authoritative and have the zone.
%%
%% Step 3: Match records
-spec resolve_authoritative(Msg, Zone, QLabels, QName, QType, CnameChain, Depth) -> Msg when
    Msg :: dns:message(),
    Zone :: erldns:zone(),
    QLabels :: dns:labels(),
    QName :: dns:dname(),
    QType :: dns:type(),
    CnameChain :: [dns:rr()],
    Depth :: non_neg_integer().
resolve_authoritative(Msg, _, _, _, _, _, 0) ->
    ?LOG_ERROR(
        #{
            what => max_resolution_depth_exceeded,
            dns_message => Msg,
            class => error,
            max_depth => ?MAX_RESOLUTION_DEPTH,
            warning => "Possible infinite loop"
        },
        ?LOG_METADATA
    ),
    Msg#dns_message{aa = true, rc = ?DNS_RCODE_SERVFAIL};
resolve_authoritative(Msg, Zone, QLabels, QName, QType, CnameChain, Depth) ->
    Resolved = erldns_zone_cache:get_records_by_name_resolved(Zone, QLabels),
    ResultMsg =
        case Resolved of
            nxdomain when [] =:= CnameChain ->
                Msg#dns_message{
                    aa = true, rc = ?DNS_RCODE_NXDOMAIN, authority = Zone#zone.authority
                };
            nxdomain ->
                % CNAME chain target doesn't exist, but the CNAME was valid: NOERROR + SOA
                Msg#dns_message{
                    aa = true, rc = ?DNS_RCODE_NOERROR, authority = Zone#zone.authority
                };
            ent ->
                Msg#dns_message{
                    aa = true, rc = ?DNS_RCODE_NOERROR, authority = Zone#zone.authority
                };
            {exact, Records} ->
                exact_match_resolution(Msg, Zone, QLabels, QType, CnameChain, Records, Depth);
            {wildcard, Records} ->
                best_match_resolution(Msg, Zone, QLabels, QName, QType, CnameChain, Records, Depth)
        end,
    maybe_add_zonecut_records(ResultMsg, Zone, QLabels, QType, Resolved).

%% DS is always answered from the parent zone (RFC 4035); do not downgrade to a
%% referral via zonecut processing (see PR #285).
maybe_add_zonecut_records(ResultMsg, _, _, ?DNS_TYPE_DS, Resolved) when is_tuple(Resolved) ->
    ResultMsg;
maybe_add_zonecut_records(ResultMsg, Zone, QLabels, _, _) ->
    AuthName = zone_authority_name(Zone),
    AuthLabels = dns_domain:split(AuthName),
    case detect_zonecut(Zone, AuthLabels, QLabels) of
        [] ->
            ResultMsg;
        ZonecutRecords ->
            FilteredCnameAnswers = lists:filter(
                fun(#dns_rr{type = RRType, data = Data}) ->
                    ?DNS_TYPE_CNAME =:= RRType andalso
                        [] =/= detect_zonecut(Zone, AuthLabels, Data#dns_rrdata_cname.dname)
                end,
                ResultMsg#dns_message.answers
            ),
            ResultMsg#dns_message{
                aa = false,
                rc = ?DNS_RCODE_NOERROR,
                authority = ZonecutRecords,
                answers = FilteredCnameAnswers
            }
    end.

-spec resolve_ent(Msg, Zone, QLabels) -> Msg when
    Msg :: dns:message(),
    Zone :: erldns:zone(),
    QLabels :: dns:labels().
resolve_ent(Message, Zone, QLabels) ->
    case erldns_zone_cache:is_record_name_in_zone_strict(Zone, QLabels) of
        false ->
            % No host name with the given record in the zone, return NXDOMAIN and include authority
            Message#dns_message{
                aa = true,
                rc = ?DNS_RCODE_NXDOMAIN,
                authority = Zone#zone.authority
            };
        true ->
            % Domain name exists in the zone, return NOERROR and include authority
            Message#dns_message{
                aa = true,
                rc = ?DNS_RCODE_NOERROR,
                authority = Zone#zone.authority
            }
    end.

%% Determine if there is a CNAME anywhere in the records with the given QName.
exact_match_resolution(Message, Zone, QLabels, QType, CnameChain, MatchedRecords, Depth) ->
    case lists:filter(fun erldns_records:is_cname/1, MatchedRecords) of
        [] ->
            % No CNAME records found in the record set for the QName
            resolve_exact_match(Message, Zone, QLabels, QType, CnameChain, MatchedRecords, Depth);
        CnameRecords ->
            % CNAME records found in the record set for the QName
            resolve_exact_match_with_cname(
                Message, Zone, QType, CnameChain, MatchedRecords, CnameRecords, Depth
            )
    end.

%% There were no CNAMEs found in the exact name matches, so now we grab the authority
%% records and find any type matches on QTYPE and continue on.
%%
%% This function will search both MatchedRecords and custom handlers.
-spec resolve_exact_match(
    Message :: dns:message(),
    Zone :: erldns:zone(),
    QLabels :: dns:labels(),
    QType :: dns:type(),
    CnameChain :: [dns:rr()],
    MatchedRecords :: [dns:rr()],
    Depth :: non_neg_integer()
) ->
    dns:message().
resolve_exact_match(Message, Zone, QLabels, QType, CnameChain, MatchedRecords, Depth) ->
    TypeMatches =
        case QType of
            ?DNS_TYPE_ANY ->
                erldns_handler:call_filters(MatchedRecords);
            _ ->
                lists:filter(erldns_records:match_type(QType), MatchedRecords)
        end,
    ExactTypeMatches =
        case TypeMatches of
            [] ->
                % No records matched the qtype, call custom handler
                erldns_handler:call_handlers(Message, QLabels, QType, MatchedRecords);
            _ ->
                % Records match qtype, use them
                TypeMatches
        end,
    AuthorityRecords = lists:filter(fun erldns_records:is_soa/1, MatchedRecords),
    ReferralRecords = lists:filter(fun erldns_records:is_ns/1, MatchedRecords),
    case {ExactTypeMatches, ReferralRecords} of
        {[], []} ->
            % There are no exact type matches and no referrals,
            % return NOERROR with the authority set
            Message#dns_message{aa = true, authority = Zone#zone.authority};
        {[], _} when QType =:= ?DNS_TYPE_DS ->
            % There were no exact type matches, but since the query type
            % was DS we still return NOERROR with the authority set
            Message#dns_message{aa = true, authority = Zone#zone.authority};
        {[], _} ->
            % There were no exact type matches,
            % but there were other name matches and there are NS records,
            % so this is an exact match referral
            resolve_exact_match_referral(
                Message, QType, MatchedRecords, ReferralRecords, AuthorityRecords
            );
        _ ->
            % There were exact matches of name and type.
            resolve_exact_type_match(
                Message, Zone, QLabels, QType, CnameChain, ExactTypeMatches, AuthorityRecords, Depth
            )
    end.

-spec resolve_exact_type_match(
    Message :: dns:message(),
    Zone :: erldns:zone(),
    QLabels :: dns:labels(),
    QType :: dns:type(),
    CnameChain :: [dns:rr()],
    MatchedRecords :: [dns:rr()],
    AuthorityRecords :: [dns:rr()],
    Depth :: non_neg_integer()
) ->
    dns:message().
resolve_exact_type_match(
    Message, _Zone, _QLabels, ?DNS_TYPE_NS, _CnameChain, [Answer | _], [], _Depth
) ->
    % NS records at this name but no SOA — this is a delegation point.
    % Return the message as-is; maybe_add_zonecut_records in resolve_authoritative
    % will detect the zone cut and produce the correct referral response.
    ?LOG_INFO(
        #{what => exact_match_for_ns_with_no_soa, qname => Answer#dns_rr.name}, ?LOG_METADATA
    ),
    Message;
resolve_exact_type_match(
    Message, _Zone, _QLabels, ?DNS_TYPE_NS, _CnameChain, MatchedRecords, _AuthorityRecords, _Depth
) ->
    % There was an exact type match for an NS query and an SOA record.
    Message#dns_message{
        aa = true,
        rc = ?DNS_RCODE_NOERROR,
        answers = Message#dns_message.answers ++ MatchedRecords
    };
resolve_exact_type_match(
    Message,
    Zone,
    QLabels,
    QType,
    CnameChain,
    [Answer | _] = MatchedRecords,
    AuthorityRecords,
    Depth
) ->
    % There was an exact type match for something other than an NS record
    % and we are authoritative because there is an SOA record.
    case erldns_zone_cache:get_delegations(Answer#dns_rr.name, QLabels) of
        [] ->
            % We are authoritative and there are no NS records here.
            Message#dns_message{
                aa = true,
                rc = ?DNS_RCODE_NOERROR,
                answers = Message#dns_message.answers ++ MatchedRecords
            };
        [#dns_rr{name = NSRecordName} | _] = NSRecords ->
            SoaRecordName = zone_authority_name(Zone),
            case dns_domain:are_equal(SoaRecordName, NSRecordName) of
                true ->
                    % The SOA record name matches the NS record name, we are at the apex,
                    % NOERROR and append the matched records to the answers
                    Message#dns_message{
                        aa = true,
                        rc = ?DNS_RCODE_NOERROR,
                        answers = Message#dns_message.answers ++ MatchedRecords
                    };
                false ->
                    % The SOA record and NS name do not match, so this may require restarting the
                    % search as the name may or may not be delegated to another zone in the cache
                    resolve_exact_type_match_delegated(
                        Message,
                        Zone,
                        QLabels,
                        QType,
                        CnameChain,
                        MatchedRecords,
                        AuthorityRecords,
                        NSRecords,
                        Depth
                    )
            end
    end.

%% There is an exact name and type match and there NS records present.
%% This may indicate the name is at the apex
%% or it may indicate that the name is delegated.
-spec resolve_exact_type_match_delegated(
    Message :: dns:message(),
    Zone :: erldns:zone(),
    QLabels :: dns:labels(),
    QType :: dns:type(),
    CnameChain :: [dns:rr()],
    MatchedRecords :: [dns:rr()],
    AuthorityRecords :: [dns:rr()],
    NSRecords :: [dns:rr()],
    Depth :: non_neg_integer()
) ->
    dns:message().
resolve_exact_type_match_delegated(
    Message,
    _Zone,
    QLabels,
    QType,
    CnameChain,
    [#dns_rr{name = AnswerName} | _] = MatchedRecords,
    _AuthorityRecords,
    [#dns_rr{name = NSRecordName} | _] = NSRecords,
    Depth
) ->
    % We are authoritative and there are NS records here.
    case dns_domain:are_equal(NSRecordName, AnswerName) of
        true ->
            % NS owner name matches answer name, thus it's a recursion, so return the message
            Message#dns_message{
                aa = false,
                rc = ?DNS_RCODE_NOERROR,
                authority = Message#dns_message.authority ++ NSRecords
            };
        false ->
            % NS name is different than the name in the matched records
            NSLabels = dns_domain:split(NSRecordName),
            case check_if_parent(NSLabels, QLabels) of
                true ->
                    % NS record name is a parent of the answer name
                    restart_delegated_query(
                        Message, NSLabels, NSRecordName, QType, CnameChain, Depth
                    );
                false ->
                    % NS record name is not a parent of the answer name
                    Message#dns_message{
                        aa = true,
                        rc = ?DNS_RCODE_NOERROR,
                        answers = Message#dns_message.answers ++ MatchedRecords,
                        additional = Message#dns_message.additional
                    }
            end
    end.

-spec resolve_exact_match_referral(
    Message :: dns:message(),
    QType :: dns:type(),
    MatchedRecords :: [dns:rr()],
    ReferralRecords :: [dns:rr()],
    AuthorityRecords :: [dns:rr()]
) ->
    dns:message().
resolve_exact_match_referral(Message, _QType, _MatchedRecords, ReferralRecords, []) ->
    % Given an exact name match where the QType is not found in the record set
    % and we are not authoritative, add the NS records to the authority section of the message.
    Message#dns_message{authority = Message#dns_message.authority ++ ReferralRecords};
resolve_exact_match_referral(
    Message, ?DNS_TYPE_ANY, MatchedRecords, _ReferralRecords, _AuthorityRecords
) ->
    % Given an exact name match and the type of ANY, return all of the matched records.
    Message#dns_message{aa = true, answers = MatchedRecords};
resolve_exact_match_referral(
    Message, ?DNS_TYPE_NS, _MatchedRecords, ReferralRecords, _AuthorityRecords
) ->
    % Given an exact name match and the type NS, where the NS records are not found in record set
    % return the NS records in the answers section of the message.
    Message#dns_message{aa = true, answers = ReferralRecords};
resolve_exact_match_referral(
    Message, ?DNS_TYPE_SOA, _MatchedRecords, _ReferralRecords, AuthorityRecords
) ->
    % Given an exact name match and the type SOA,
    % where the SOA record is not found in the records set,
    % return the SOA records in the answers section of the message.
    Message#dns_message{aa = true, answers = AuthorityRecords};
resolve_exact_match_referral(Message, _, _MatchedRecords, _ReferralRecords, AuthorityRecords) ->
    % Given an exact name match where the QType is not found in the record set
    % and is not ANY, SOA or NS, return the SOA records for the zone in the authority section
    % of the message and set the RC to NOERROR.
    Message#dns_message{
        aa = true,
        rc = ?DNS_RCODE_NOERROR,
        authority = AuthorityRecords
    }.

-spec resolve_exact_match_with_cname(
    Message :: dns:message(),
    Zone :: erldns:zone(),
    QType :: dns:type(),
    CnameChain :: [dns:rr()],
    MatchedRecords :: [dns:rr()],
    CnameRecords :: [dns:rr()],
    Depth :: non_neg_integer()
) ->
    dns:message().
%% There is a CNAME record and the request was for a CNAME record
%% so append the CNAME records to the answers section.
resolve_exact_match_with_cname(
    Message, _Zone, ?DNS_TYPE_CNAME, _CnameChain, _MatchedRecords, CnameRecords, _Depth
) ->
    Message#dns_message{aa = true, answers = Message#dns_message.answers ++ CnameRecords};
%% For ANY queries, return the CNAME record without following the chain.
%% ANY means "return all records at this name" and the CNAME is the record here.
resolve_exact_match_with_cname(
    Message, _Zone, ?DNS_TYPE_ANY, _CnameChain, _MatchedRecords, CnameRecords, _Depth
) ->
    Message#dns_message{aa = true, answers = Message#dns_message.answers ++ CnameRecords};
%% There is a CNAME record, however the QType is not CNAME or ANY,
%% check for a CNAME loop before continuing.
resolve_exact_match_with_cname(
    Message, Zone, QType, CnameChain, _MatchedRecords, [CnameRecord | _] = CnameRecords, Depth
) ->
    case lists:member(CnameRecord, CnameChain) of
        true ->
            % Indicates a CNAME loop. The response code is a SERVFAIL in this case.
            Message#dns_message{aa = true, rc = ?DNS_RCODE_SERVFAIL};
        false ->
            % No CNAME loop, restart the query with the CNAME content.
            Name = CnameRecord#dns_rr.data#dns_rrdata_cname.dname,
            Labels = dns_domain:split(Name),
            Msg1 = Message#dns_message{
                aa = true, answers = Message#dns_message.answers ++ CnameRecords
            },
            restart_query(Msg1, Zone, Labels, Name, QType, CnameRecords ++ CnameChain, Depth)
    end.

-spec best_match_resolution(
    Message :: dns:message(),
    Zone :: erldns:zone(),
    QLabels :: dns:labels(),
    QName :: dns:dname(),
    QType :: dns:type(),
    CnameChain :: [dns:rr()],
    BestMatchRecords :: [dns:rr()],
    Depth :: non_neg_integer()
) ->
    dns:message().
best_match_resolution(Message, Zone, QLabels, QName, QType, CnameChain, BestMatchRecords, Depth) ->
    % There was no exact match for the QName,
    % so we use the best matches that were returned by the
    % get_records_by_name_wildcard_strict() function.
    ReferralRecords = lists:filter(fun erldns_records:is_ns/1, BestMatchRecords),
    case ReferralRecords of
        [] ->
            % There were no NS records in the best matches.
            resolve_best_match(
                Message, Zone, QLabels, QName, QType, CnameChain, BestMatchRecords, Depth
            );
        _ ->
            % There were NS records in the best matches, so this is a referral.
            resolve_best_match_referral(
                Message, Zone, QLabels, QType, CnameChain, BestMatchRecords, ReferralRecords
            )
    end.

%% There is no referral, so check to see if there is a wildcard.
%%
%% If there is a wildcard present,
%% then the resolver needs to continue to handle various possible types.
%%
%% If there is no wildcard present and the qname matches the original question then return NXDOMAIN.
%%
%% If there is no wildcard present and the qname does not match the original question
%% then return NOERROR and include root hints in the additional section if necessary.
-spec resolve_best_match(
    Message :: dns:message(),
    Zone :: erldns:zone(),
    QLabels :: dns:labels(),
    QName :: dns:dname(),
    QType :: dns:type(),
    CnameChain :: [dns:rr()],
    BestMatchRecords :: [dns:rr()],
    Depth :: non_neg_integer()
) ->
    dns:message().
resolve_best_match(Message, Zone, QLabels, QName, QType, CnameChain, BestMatchRecords, Depth) ->
    case lists:any(erldns_records:match_wildcard(), BestMatchRecords) of
        true ->
            % It's a wildcard match
            CnameRecords = lists:filter(fun erldns_records:is_cname/1, BestMatchRecords),
            ReplaceNames = lists:map(erldns_records:replace_name(QName), CnameRecords),
            resolve_best_match_with_wildcard(
                Message,
                Zone,
                QLabels,
                QName,
                QType,
                CnameChain,
                BestMatchRecords,
                ReplaceNames,
                Depth
            );
        false ->
            % It's not a wildcard
            #dns_message{questions = [#dns_query{name = QuestionName} | _]} = Message,
            % TODO this logic can be moved up higher in processing potentially.
            case dns_domain:are_equal(QName, QuestionName) of
                true ->
                    % We are authoritative but there is no match on name and type,
                    % so respond with NXDOMAIN
                    Message#dns_message{
                        rc = ?DNS_RCODE_NXDOMAIN,
                        authority = Zone#zone.authority,
                        aa = true
                    };
                false ->
                    % This happens when we have a CNAME to an out-of-balliwick hostname and the
                    % query is for something other than CNAME.
                    % Note that the response is still NOERROR here.
                    %
                    % In the dnstest suite, this is hit by cname_to_unauth_any (and others)
                    optionally_add_root_hints(Message)
            end
    end.

-spec resolve_best_match_with_wildcard(
    Message :: dns:message(),
    Zone :: erldns:zone(),
    QLabels :: dns:labels(),
    QName :: dns:dname(),
    QType :: dns:type(),
    CnameChain :: [dns:rr()],
    BestMatchRecords :: [dns:rr()],
    CnameRecords :: [dns:rr()],
    Depth :: non_neg_integer()
) ->
    dns:message().
resolve_best_match_with_wildcard(
    Message, Zone, QLabels, QName, QType, _CnameChain, MatchedRecords, [], _Depth
) ->
    % Handle best match resolving with a wildcard name in the zone.
    TypeMatchedRecords =
        case QType of
            ?DNS_TYPE_ANY ->
                erldns_handler:call_filters(MatchedRecords);
            _ ->
                lists:filter(erldns_records:match_type(QType), MatchedRecords)
        end,
    ReplacementNameFun = erldns_records:replace_name(QName),
    case lists:map(ReplacementNameFun, TypeMatchedRecords) of
        [] ->
            % There is no exact type matches for the original qtype,
            % ask the custom handlers for their records.
            HandlerRecords = erldns_handler:call_handlers(Message, QLabels, QType, MatchedRecords),
            case lists:map(ReplacementNameFun, HandlerRecords) of
                [] ->
                    % Custom handlers returned no answers,
                    % so set the authority section of the response and return NOERROR
                    Message#dns_message{aa = true, authority = Zone#zone.authority};
                NewRecords ->
                    % Custom handlers returned answers
                    Message#dns_message{
                        aa = true, answers = Message#dns_message.answers ++ NewRecords
                    }
            end;
        TypeMatches ->
            % There is an exact type match
            Message#dns_message{aa = true, answers = Message#dns_message.answers ++ TypeMatches}
    end;
resolve_best_match_with_wildcard(
    Message, Zone, QLabels, QName, QType, CnameChain, BestMatchRecords, CnameRecords, Depth
) ->
    % It is a wildcard CNAME
    resolve_best_match_with_wildcard_cname(
        Message, Zone, QLabels, QName, QType, CnameChain, BestMatchRecords, CnameRecords, Depth
    ).

% Handle the case where the wildcard is a CNAME in the zone.
% If the QType was CNAME then answer, otherwise determine if the CNAME should be followed
-spec resolve_best_match_with_wildcard_cname(
    Message :: dns:message(),
    Zone :: erldns:zone(),
    QLabels :: dns:labels(),
    QName :: dns:dname(),
    QType :: dns:type(),
    CnameChain :: [dns:rr()],
    BestMatchRecords :: [dns:rr()],
    CnameRecords :: [dns:rr()],
    Depth :: non_neg_integer()
) ->
    dns:message().
resolve_best_match_with_wildcard_cname(
    Message,
    _Zone,
    _QLabels,
    _QName,
    ?DNS_TYPE_CNAME,
    _CnameChain,
    _BestMatchRecords,
    CnameRecords,
    _Depth
) ->
    Message#dns_message{aa = true, answers = Message#dns_message.answers ++ CnameRecords};
resolve_best_match_with_wildcard_cname(
    Message,
    Zone,
    _QLabels,
    _QName,
    QType,
    CnameChain,
    _BestMatchRecords,
    [CnameRecord | _] = CnameRecords,
    Depth
) ->
    % There should only be one CNAME. Multiple CNAMEs kill unicorns.
    case lists:member(CnameRecord, CnameChain) of
        true ->
            % Indicates CNAME loop
            Message#dns_message{aa = true, rc = ?DNS_RCODE_SERVFAIL};
        false ->
            % Follow the CNAME
            Name = CnameRecord#dns_rr.data#dns_rrdata_cname.dname,
            Labels = dns_domain:split(Name),
            Msg1 = Message#dns_message{
                aa = true, answers = Message#dns_message.answers ++ CnameRecords
            },
            restart_query(Msg1, Zone, Labels, Name, QType, CnameRecords ++ CnameChain, Depth)
    end.

% There are referral records
-spec resolve_best_match_referral(
    Message :: dns:message(),
    Zone :: erldns:zone(),
    QLabels :: dns:labels(),
    QType :: dns:type(),
    CnameChain :: [dns:rr()],
    BestMatchRecords :: [dns:rr()],
    CnameRecords :: [dns:rr()]
) ->
    dns:message().
resolve_best_match_referral(
    Message, Zone, QLabels, QType, CnameChain, BestMatchRecords, ReferralRecords
) ->
    Authority = lists:filter(fun erldns_records:is_soa/1, BestMatchRecords),
    case {QType, Authority, CnameChain} of
        {_, [], []} ->
            % We are authoritative for the name since there was an SOA record
            % in the best match results.
            resolve_ent(Message, Zone, QLabels);
        {_, _, []} ->
            % Indicate that we are not authoritative for the name
            % as there were no SOA records in the best-match results.
            % The name has thus been delegated to another authority.
            Message#dns_message{
                aa = false, authority = Message#dns_message.authority ++ ReferralRecords
            };
        {?DNS_TYPE_ANY, _, _} ->
            % We are authoritative and the QType is ANY, return the original message
            Message;
        _ ->
            % We are authoritative and the QType is something other than ANY,
            % set the authority in the response
            Message#dns_message{authority = Authority}
    end.

% Continue the CNAME chain only when the target is under the current zone apex (suffix) and the
% name is considered in-zone by the zone cache (same rules as is_in_any_zone/1). We check
% check_if_parent/2 first so we skip the zone-cache walk when the target is out of bailiwick for
% this zone — the outcome is the same as is_in_any_zone=false in that case.
-spec restart_query(
    Message :: dns:message(),
    Zone :: erldns:zone(),
    Labels :: dns:labels(),
    Name :: dns:dname(),
    QType :: dns:type(),
    CnameChain :: [dynamic()],
    Depth :: non_neg_integer()
) ->
    dns:message().
restart_query(Message, Zone, Labels, Name, QType, CnameChain, Depth) ->
    maybe
        true ?= check_if_parent(Zone#zone.labels, Labels),
        true ?= erldns_zone_cache:is_in_any_zone(Labels),
        resolve_authoritative(Message, Zone, Labels, Name, QType, CnameChain, Depth - 1)
    else
        _ ->
            Message
    end.

-spec restart_delegated_query(
    Message :: dns:message(),
    Labels :: dns:labels(),
    QName :: dns:dname(),
    QType :: dns:type(),
    CnameChain :: [dns:rr()],
    Depth :: non_neg_integer()
) ->
    dns:message().
restart_delegated_query(Message, QLabels, QName, QType, CnameChain, Depth) ->
    case erldns_zone_cache:get_authoritative_zone(QLabels) of
        #zone{} = AuthZone ->
            resolve_authoritative(Message, AuthZone, QLabels, QName, QType, CnameChain, Depth - 1);
        _NotFound ->
            Message
    end.

%% Utility functions

%% If root hints are enabled, return an updated message with the root hints.
-spec optionally_add_root_hints(dns:message()) -> dns:message().
optionally_add_root_hints(Message) ->
    case erldns_config:use_root_hints() of
        true ->
            {Authority, Additional} = erldns_records:root_hints(),
            Message#dns_message{
                authority = Authority, additional = Message#dns_message.additional ++ Additional
            };
        _ ->
            Message
    end.

%% Returns true if the first domain name is a parent of the second domain name.
check_if_parent(MaybeParent, MaybeChild) when is_list(MaybeParent), is_list(MaybeChild) ->
    lists:suffix(MaybeParent, MaybeChild).

%% See if additional processing is necessary.
additional_processing(#dns_message{answers = Answers, authority = Authority} = Message, Zone) ->
    RequiresAdditionalProcessing = requires_additional_processing(Answers, Authority, []),
    additional_processing(Message, Zone, RequiresAdditionalProcessing).

%% No records require additional processing.
additional_processing(Message, _Zone, []) ->
    Message;
%% There are records with names that require additional processing.
additional_processing(Message, Zone, Names) ->
    RRs = lists:flatmap(fun erldns_zone_cache:get_records_by_name/1, Names),
    Records = lists:filter(erldns_records:match_types([?DNS_TYPE_A, ?DNS_TYPE_AAAA]), RRs),
    additional_processing(Message, Zone, Names, Records).

%% No additional A records were found, so just return the message.
additional_processing(Message, _Zone, _Names, []) ->
    Message;
%% Additional A records were found, so we add them to the additional section.
additional_processing(Message, _Zone, _Names, Records) ->
    Message#dns_message{additional = Message#dns_message.additional ++ Records}.

%% Given a list of answers find the names that require additional processing.
-spec requires_additional_processing([dns:rr()], [dns:rr()], [dns:dname()]) -> [dns:dname()].
requires_additional_processing([], [], Acc) ->
    Acc;
requires_additional_processing([#dns_rr{data = #dns_rrdata_ns{dname = Dname}} | Rest], More, Acc) ->
    requires_additional_processing(Rest, More, [Dname | Acc]);
requires_additional_processing(
    [#dns_rr{data = #dns_rrdata_mx{exchange = Exchange}} | Rest], More, Acc
) ->
    requires_additional_processing(Rest, More, [Exchange | Acc]);
requires_additional_processing([_ | Rest], More, Acc) ->
    requires_additional_processing(Rest, More, Acc);
requires_additional_processing([], More, Acc) ->
    requires_additional_processing(More, [], Acc).

% Extract the name from the first record in the list.
zone_authority_name(#zone{authority = [Record | _]}) ->
    Record#dns_rr.name.

% Find NS records that represent a zone cut.
detect_zonecut(Zone, AuthLabels, QName) when is_binary(QName) ->
    detect_zonecut(Zone, AuthLabels, dns_domain:split(QName));
detect_zonecut(Zone, AuthLabels, QLabels) when is_list(QLabels) ->
    do_detect_zonecut(Zone, AuthLabels, QLabels).

do_detect_zonecut(_, _, []) ->
    [];
do_detect_zonecut(_, _, [_]) ->
    [];
do_detect_zonecut(Zone, AuthLabels, [_ | ParentLabels] = Labels) ->
    case dns_domain:are_equal_labels(AuthLabels, Labels) of
        true ->
            [];
        false ->
            case erldns_zone_cache:get_records_by_name_and_type(Zone, Labels, ?DNS_TYPE_NS) of
                [] ->
                    do_detect_zonecut(Zone, AuthLabels, ParentLabels);
                ZonecutNSRecords ->
                    ZonecutNSRecords
            end
    end.

complete_response(Msg) ->
    Msg#dns_message{
        qr = true,
        ad = false,
        cd = false
    }.
