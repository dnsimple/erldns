-module(erldns_resolver).
-moduledoc """
Resolve a DNS query.

Assumes that the DNS message contains exactly one query.

## Referrals

A name at or below a zone cut is answered with a referral (RFC 1034 §4.3.2): the delegation's NS
RRset in the authority section, the CNAMEs followed to get there in the answer section, and nothing
from below the cut. The delegation is put in the pipeline opts as `zonecut`, the labels of its name
or `none` for an authoritative answer, so that later pipes such as `m:erldns_dnssec` know what the
response refers to without inferring it from the message. A DS query for the delegation name itself
is answered by this zone, whose data the DS RRset is (RFC 4035 §3.1.4.1).

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

-doc "The delegation a response refers to, as the labels of its name, or `none`.".
-type zonecut() :: none | dns:labels().
-export_type([zonecut/0]).

%% What resolving one name yields: an answer, or a CNAME chain to continue from, with the CNAME
%% RRset already appended to the answer section.
-type resolution() :: dns:message() | {cname, dns:message(), [dns:rr(), ...]}.

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
    Opts#{auth_zone => zone_not_found, zonecut => none}.

-doc "`c:erldns_pipeline:call/2` callback.".
-spec call(dns:message(), erldns_pipeline:opts()) -> erldns_pipeline:return().
call(Msg, #{resolved := false, query_labels := QLabels, query_type := QType} = Opts) ->
    %% Search the available zones for the zone which is the nearest ancestor to QLabels
    case erldns_zone_cache:get_authoritative_zone(QLabels, QType) of
        #zone{} = Zone ->
            #dns_message{questions = [#dns_query{name = QName}]} = Msg,
            {Msg1, Zonecut} = resolve(Msg, Zone, QLabels, QName, QType),
            Msg2 = complete_response(Msg1),
            {Msg2, Opts#{auth_zone => Zone, resolved => true, zonecut => Zonecut}};
        Error when Error =:= not_authoritative; Error =:= zone_not_found ->
            Msg1 = Msg#dns_message{aa = false, rc = ?DNS_RCODE_REFUSED},
            Msg2 = optionally_add_root_hints(Msg1),
            complete_response(Msg2)
    end;
call(Msg, _) ->
    Msg.

%% Start the resolution process on the given question. Assumes only one question. Whatever the
%% request carried in its answer and authority sections is not ours to answer with.
%% Handlers can escape the control flow by throwing `{error, rcode, RCODE}`.
-spec resolve(dns:message(), erldns:zone(), dns:labels(), dns:dname(), dns:type()) ->
    {dns:message(), zonecut()}.
resolve(Msg0, Zone, QLabels, QName, QType) ->
    Msg = Msg0#dns_message{answers = [], authority = []},
    try
        {Msg1, Zonecut} =
            resolve_authoritative(Msg, Zone, QLabels, QName, QType, [], ?MAX_RESOLUTION_DEPTH),
        {additional_processing(Msg1, Zone), Zonecut}
    catch
        throw:{error, rcode, RC} ->
            telemetry:execute([erldns, pipeline, resolver, error], #{count => 1}, #{rc => RC}),
            {Msg#dns_message{aa = false, rc = RC}, none};
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
            {Msg#dns_message{aa = false, rc = ?DNS_RCODE_SERVFAIL}, none}
    end.

%% RFC 1034 §4.3.2 step 3b: a name at or below a zone cut takes the query out of this zone's data
%% and is referred to the delegation before anything stored there is looked at. A DS query for the
%% delegation name itself stays: the DS RRset is the parent's (RFC 4035 §3.1.4.1).
-spec resolve_authoritative(Msg, Zone, QLabels, QName, QType, CnameChain, Depth) -> Return when
    Msg :: dns:message(),
    Zone :: erldns:zone(),
    QLabels :: dns:labels(),
    QName :: dns:dname(),
    QType :: dns:type(),
    CnameChain :: [dns:rr()],
    Depth :: non_neg_integer(),
    Return :: {dns:message(), zonecut()}.
resolve_authoritative(Msg, Zone, QLabels, QName, QType, CnameChain, Depth) ->
    case erldns_zone_cache:get_zonecut(Zone, QLabels) of
        {QLabels, _} when QType =:= ?DNS_TYPE_DS ->
            resolve_name(Msg, Zone, QLabels, QName, QType, CnameChain, Depth);
        {CutLabels, NSRecords} ->
            Referral = Msg#dns_message{
                aa = false, rc = ?DNS_RCODE_NOERROR, authority = NSRecords
            },
            {Referral, CutLabels};
        none ->
            resolve_name(Msg, Zone, QLabels, QName, QType, CnameChain, Depth)
    end.

%% An SOA was found, thus we are authoritative and have the zone.
%%
%% Step 3: Match records
-spec resolve_name(Msg, Zone, QLabels, QName, QType, CnameChain, Depth) -> Return when
    Msg :: dns:message(),
    Zone :: erldns:zone(),
    QLabels :: dns:labels(),
    QName :: dns:dname(),
    QType :: dns:type(),
    CnameChain :: [dns:rr()],
    Depth :: non_neg_integer(),
    Return :: {dns:message(), zonecut()}.
resolve_name(Msg, _, _, _, _, _, 0) ->
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
    {Msg#dns_message{aa = true, rc = ?DNS_RCODE_SERVFAIL}, none};
resolve_name(Msg, Zone, QLabels, QName, QType, CnameChain, Depth) ->
    case erldns_zone_cache:get_records_by_name_resolved(Zone, QLabels) of
        nxdomain when [] =:= CnameChain ->
            Msg1 = Msg#dns_message{
                aa = true, rc = ?DNS_RCODE_NXDOMAIN, authority = Zone#zone.authority
            },
            {Msg1, none};
        nxdomain ->
            % CNAME chain target doesn't exist, but the CNAME was valid: NOERROR + SOA
            Msg1 = Msg#dns_message{
                aa = true, rc = ?DNS_RCODE_NOERROR, authority = Zone#zone.authority
            },
            {Msg1, none};
        ent ->
            Msg1 = Msg#dns_message{
                aa = true, rc = ?DNS_RCODE_NOERROR, authority = Zone#zone.authority
            },
            {Msg1, none};
        {exact, Records} ->
            Resolution = exact_match_resolution(Msg, Zone, QType, CnameChain, Records),
            follow(Resolution, Zone, QType, CnameChain, Depth);
        {wildcard, Records} ->
            Resolution = best_match_resolution(
                Msg, Zone, QLabels, QName, QType, CnameChain, Records
            ),
            follow(Resolution, Zone, QType, CnameChain, Depth)
    end.

%% Continue a CNAME chain at its target when that is under this zone's apex and the zone cache
%% knows the name (same rules as is_in_any_zone/1); the suffix check first skips the cache walk
%% for a target out of bailiwick. Otherwise the chain ends with what has been collected.
-spec follow(resolution(), erldns:zone(), dns:type(), [dns:rr()], non_neg_integer()) ->
    {dns:message(), zonecut()}.
follow({cname, Msg, [CnameRecord | _] = CnameRecords}, Zone, QType, CnameChain, Depth) ->
    Name = CnameRecord#dns_rr.data#dns_rrdata_cname.dname,
    Labels = dns_domain:split(Name),
    maybe
        true ?= lists:suffix(Zone#zone.labels, Labels),
        true ?= erldns_zone_cache:is_in_any_zone(Labels),
        resolve_authoritative(
            Msg, Zone, Labels, Name, QType, CnameRecords ++ CnameChain, Depth - 1
        )
    else
        _ ->
            {Msg, none}
    end;
follow(#dns_message{} = Msg, _, _, _, _) ->
    {Msg, none}.

%% Determine if there is a CNAME anywhere in the records with the given QName.
-spec exact_match_resolution(
    Message :: dns:message(),
    Zone :: erldns:zone(),
    QType :: dns:type(),
    CnameChain :: [dns:rr()],
    MatchedRecords :: [dns:rr()]
) ->
    resolution().
exact_match_resolution(Message, Zone, QType, CnameChain, MatchedRecords) ->
    case lists:filter(fun erldns_records:is_cname/1, MatchedRecords) of
        [] ->
            % No CNAME records found in the record set for the QName
            resolve_exact_match(Message, Zone, QType, MatchedRecords);
        CnameRecords ->
            % CNAME records found in the record set for the QName
            resolve_exact_match_with_cname(Message, QType, CnameChain, CnameRecords)
    end.

%% No CNAME at the name: answer the records of the QTYPE, or NODATA with the SOA. Any zone cut was
%% met in resolve_authoritative/7, so an NS RRset here is the apex one and a DS is this zone's own.
-spec resolve_exact_match(
    Message :: dns:message(),
    Zone :: erldns:zone(),
    QType :: dns:type(),
    MatchedRecords :: [dns:rr()]
) ->
    dns:message().
resolve_exact_match(Message, Zone, QType, MatchedRecords) ->
    % Custom record types (URL/POOL) are synthesized by pipeline stages after the resolver, so the
    % resolver only matches the qtype against the zone records and returns NODATA otherwise.
    ExactTypeMatches =
        case QType of
            ?DNS_TYPE_ANY ->
                MatchedRecords;
            _ ->
                lists:filter(erldns_records:match_type(QType), MatchedRecords)
        end,
    case ExactTypeMatches of
        [] ->
            Message#dns_message{aa = true, authority = Zone#zone.authority};
        _ ->
            Message#dns_message{
                aa = true,
                rc = ?DNS_RCODE_NOERROR,
                answers = Message#dns_message.answers ++ ExactTypeMatches
            }
    end.

-spec resolve_exact_match_with_cname(
    Message :: dns:message(),
    QType :: dns:type(),
    CnameChain :: [dns:rr()],
    CnameRecords :: [dns:rr(), ...]
) ->
    resolution().
%% The request was for the CNAME itself, or for ANY, which means "all records at this name":
%% the CNAME is the answer and the chain is not followed.
resolve_exact_match_with_cname(Message, QType, _CnameChain, CnameRecords) when
    QType =:= ?DNS_TYPE_CNAME; QType =:= ?DNS_TYPE_ANY
->
    Message#dns_message{aa = true, answers = Message#dns_message.answers ++ CnameRecords};
%% Otherwise follow the chain, unless it loops back on itself.
resolve_exact_match_with_cname(Message, _QType, CnameChain, [CnameRecord | _] = CnameRecords) ->
    case lists:member(CnameRecord, CnameChain) of
        true ->
            % Indicates a CNAME loop. The response code is a SERVFAIL in this case.
            Message#dns_message{aa = true, rc = ?DNS_RCODE_SERVFAIL};
        false ->
            Msg1 = Message#dns_message{
                aa = true, answers = Message#dns_message.answers ++ CnameRecords
            },
            {cname, Msg1, CnameRecords}
    end.

-spec best_match_resolution(
    Message :: dns:message(),
    Zone :: erldns:zone(),
    QLabels :: dns:labels(),
    QName :: dns:dname(),
    QType :: dns:type(),
    CnameChain :: [dns:rr()],
    BestMatchRecords :: [dns:rr()]
) ->
    resolution().
best_match_resolution(Message, Zone, QLabels, QName, QType, CnameChain, BestMatchRecords) ->
    % There was no exact match for the QName,
    % so we use the best matches that were returned by the
    % get_records_by_name_wildcard_strict() function.
    ReferralRecords = lists:filter(fun erldns_records:is_ns/1, BestMatchRecords),
    case ReferralRecords of
        [] ->
            % There were no NS records in the best matches.
            resolve_best_match(Message, Zone, QName, QType, CnameChain, BestMatchRecords);
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
    QName :: dns:dname(),
    QType :: dns:type(),
    CnameChain :: [dns:rr()],
    BestMatchRecords :: [dns:rr()]
) ->
    resolution().
resolve_best_match(Message, Zone, QName, QType, CnameChain, BestMatchRecords) ->
    case lists:any(erldns_records:match_wildcard(), BestMatchRecords) of
        true ->
            % It's a wildcard match
            CnameRecords = lists:filter(fun erldns_records:is_cname/1, BestMatchRecords),
            ReplaceNames = lists:map(erldns_records:replace_name(QName), CnameRecords),
            resolve_best_match_with_wildcard(
                Message, Zone, QName, QType, CnameChain, BestMatchRecords, ReplaceNames
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
    QName :: dns:dname(),
    QType :: dns:type(),
    CnameChain :: [dns:rr()],
    BestMatchRecords :: [dns:rr()],
    CnameRecords :: [dns:rr()]
) ->
    resolution().
resolve_best_match_with_wildcard(Message, Zone, QName, QType, _CnameChain, MatchedRecords, []) ->
    % Handle best match resolving with a wildcard name in the zone.
    TypeMatchedRecords =
        case QType of
            ?DNS_TYPE_ANY ->
                MatchedRecords;
            _ ->
                lists:filter(erldns_records:match_type(QType), MatchedRecords)
        end,
    ReplacementNameFun = erldns_records:replace_name(QName),
    case lists:map(ReplacementNameFun, TypeMatchedRecords) of
        [] ->
            % There is no exact type matches for the original qtype,
            % potentially upcoming pipelines will extend
            Message#dns_message{aa = true, authority = Zone#zone.authority};
        TypeMatches ->
            % There is an exact type match
            Message#dns_message{aa = true, answers = Message#dns_message.answers ++ TypeMatches}
    end;
resolve_best_match_with_wildcard(
    Message, _Zone, _QName, QType, CnameChain, _BestMatchRecords, CnameRecords
) ->
    % It is a wildcard CNAME
    resolve_best_match_with_wildcard_cname(Message, QType, CnameChain, CnameRecords).

% Handle the case where the wildcard is a CNAME in the zone.
% If the QType was CNAME then answer, otherwise determine if the CNAME should be followed
-spec resolve_best_match_with_wildcard_cname(
    Message :: dns:message(),
    QType :: dns:type(),
    CnameChain :: [dns:rr()],
    CnameRecords :: [dns:rr(), ...]
) ->
    resolution().
resolve_best_match_with_wildcard_cname(Message, ?DNS_TYPE_CNAME, _CnameChain, CnameRecords) ->
    Message#dns_message{aa = true, answers = Message#dns_message.answers ++ CnameRecords};
resolve_best_match_with_wildcard_cname(
    Message, _QType, CnameChain, [CnameRecord | _] = CnameRecords
) ->
    % There should only be one CNAME. Multiple CNAMEs kill unicorns.
    case lists:member(CnameRecord, CnameChain) of
        true ->
            % Indicates CNAME loop
            Message#dns_message{aa = true, rc = ?DNS_RCODE_SERVFAIL};
        false ->
            % Follow the CNAME
            Msg1 = Message#dns_message{
                aa = true, answers = Message#dns_message.answers ++ CnameRecords
            },
            {cname, Msg1, CnameRecords}
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

complete_response(Msg) ->
    Msg1 = Msg#dns_message{
        qr = true,
        ad = false,
        cd = false
    },
    erldns_records:rewrite_soa_ttl(Msg1).
