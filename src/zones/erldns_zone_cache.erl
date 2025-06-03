-module(erldns_zone_cache).
-moduledoc """
A cache holding all of the zone data.

Write operations occur through the cache process mailbox, whereas read
operations occur directly through the underlying data store.
""".

-behaviour(gen_server).

-include_lib("dns_erlang/include/dns.hrl").
-include_lib("kernel/include/logger.hrl").

-include("erldns.hrl").

-export([
    find_zone/1,
    find_zone/2,
    get_zone/1,
    get_authority/1,
    get_delegations/1,
    get_zone_records/1,
    get_records_by_name/1,
    get_records_by_name_and_type/2,
    in_zone/1,
    record_name_in_zone/2,
    zone_names_and_versions/0,
    get_rrset_sync_counter/3
]).

-export([get_zone_with_records/1]).

-export([
    put_zone/1,
    put_zone/2,
    delete_zone/1,
    update_zone_records_and_digest/3,
    put_zone_rrset/4,
    delete_zone_rrset/5
]).

-export([create/1]).

-export([start_link/0, init/1, handle_call/3, handle_cast/2]).

% ----------------------------------------------------------------------------------------------------
% Read API

-doc "Call to a module's create. Creates a new table.".
-spec create(atom()) -> ok | {error, Reason :: term()}.
create(Name = zones) ->
    create_ets_table(Name, set);
create(Name = zone_records_typed) ->
    create_ets_table(Name, ordered_set);
create(Name = authorities) ->
    create_ets_table(Name, set);
create(Name = sync_counters) ->
    create_ets_table(Name, set).

-doc "Find a zone for a given qname.".
-spec find_zone(dns:dname()) ->
    erldns:zone() | {error, zone_not_found} | {error, not_authoritative}.
find_zone(Qname) ->
    find_zone(erldns:normalize_name(Qname), get_authority(Qname)).

-doc "Find a zone for a given qname.".
-spec find_zone(dns:dname(), {error, any()} | {ok, dns:rr()} | [dns:rr()] | dns:rr()) ->
    erldns:zone() | {error, zone_not_found} | {error, not_authoritative}.
find_zone(Qname, {error, _}) ->
    find_zone(Qname, []);
find_zone(Qname, {ok, Authority}) ->
    find_zone(Qname, Authority);
find_zone(_Qname, []) ->
    {error, not_authoritative};
find_zone(Qname, Authorities) when is_list(Authorities) ->
    find_zone(Qname, lists:last(Authorities));
find_zone(Qname, Authority) when is_record(Authority, dns_rr) ->
    Name = erldns:normalize_name(Qname),
    case dns:dname_to_labels(Name) of
        [] ->
            {error, zone_not_found};
        [_ | Labels] ->
            case get_zone(Name) of
                {ok, Zone} ->
                    Zone;
                {error, zone_not_found} ->
                    case Name =:= Authority#dns_rr.name of
                        true ->
                            {error, zone_not_found};
                        false ->
                            find_zone(dns:labels_to_dname(Labels), Authority)
                    end
            end
    end.

-doc """
Get a zone for the specific name. This function will not attempt to resolve
the dname in any way, it will simply look up the name in the underlying data store.
""".
-spec get_zone(dns:dname()) -> {ok, erldns:zone()} | {error, zone_not_found}.
get_zone(Name) ->
    NormalizedName = erldns:normalize_name(Name),
    case ets:lookup(zones, NormalizedName) of
        [{NormalizedName, Zone}] ->
            {ok, Zone#zone{
                name = NormalizedName,
                records = [],
                records_by_name = trimmed
            }};
        _ ->
            {error, zone_not_found}
    end.

-doc """
Get a zone for the specific name, including the records for the zone.

@deprecated Use {@link erldns_zone_cache:get_zone/1} to get the zone meta data and
{@link erldns_zone_cache:get_zone_records/1} to get the records for the zone.
""".
-spec get_zone_with_records(dns:dname()) -> {ok, erldns:zone()} | {error, zone_not_found}.
get_zone_with_records(Name) ->
    NormalizedName = erldns:normalize_name(Name),
    case ets:lookup(zones, NormalizedName) of
        [{NormalizedName, Zone}] ->
            {ok, Zone};
        _ ->
            {error, zone_not_found}
    end.

-doc "Find the SOA record for the given DNS question.".
-spec get_authority(dns:message() | dns:dname()) ->
    {error, no_question} | {error, authority_not_found} | {ok, dns:authority()}.
get_authority(Message) when is_record(Message, dns_message) ->
    case Message#dns_message.questions of
        [] ->
            {error, no_question};
        Questions ->
            Question = lists:last(Questions),
            get_authority(Question#dns_query.name)
    end;
get_authority(Name) ->
    case find_zone_in_cache(erldns:normalize_name(Name)) of
        {ok, Zone} ->
            {ok, Zone#zone.authority};
        _ ->
            {error, authority_not_found}
    end.

-doc """
Get the list of NS and glue records for the given name.

This function will always return a list, even if it is empty.
""".
-spec get_delegations(dns:dname()) -> [dns:rr()] | [].
get_delegations(Name) ->
    case find_zone_in_cache(Name) of
        {ok, Zone} ->
            Records =
                lists:flatten(
                    ets:select(
                        zone_records_typed,
                        [
                            {
                                {
                                    {
                                        erldns:normalize_name(Zone#zone.name),
                                        erldns:normalize_name(Name),
                                        ?DNS_TYPE_NS
                                    },
                                    '$1'
                                },
                                [],
                                ['$$']
                            }
                        ]
                    )
                ),
            lists:filter(erldns_records:match_delegation(Name), Records);
        _ ->
            []
    end.

-doc "Get all records for the given zone.".
-spec get_zone_records(dns:dname()) -> [dns:rr()].
get_zone_records(Name) ->
    case find_zone_in_cache(Name) of
        {ok, Zone} ->
            lists:flatten(
                ets:select(
                    zone_records_typed,
                    [{{{erldns:normalize_name(Zone#zone.name), '_', '_'}, '$1'}, [], ['$$']}]
                )
            );
        _ ->
            []
    end.

-doc "Get all records for the given type and given name.".
-spec get_records_by_name_and_type(dns:dname(), dns:type()) -> [dns:rr()].
get_records_by_name_and_type(Name, Type) ->
    case find_zone_in_cache(Name) of
        {ok, Zone} ->
            lists:flatten(
                ets:select(
                    zone_records_typed,
                    [
                        {
                            {
                                {
                                    erldns:normalize_name(Zone#zone.name),
                                    erldns:normalize_name(Name),
                                    Type
                                },
                                '$1'
                            },
                            [],
                            ['$$']
                        }
                    ]
                )
            );
        _ ->
            []
    end.

-doc "Return the record set for the given dname.".
-spec get_records_by_name(dns:dname()) -> [dns:rr()].
get_records_by_name(Name) ->
    case find_zone_in_cache(Name) of
        {ok, Zone} ->
            lists:flatten(
                ets:select(
                    zone_records_typed,
                    [
                        {
                            {
                                {
                                    erldns:normalize_name(Zone#zone.name),
                                    erldns:normalize_name(Name),
                                    '_'
                                },
                                '$1'
                            },
                            [],
                            ['$$']
                        }
                    ]
                )
            );
        _ ->
            []
    end.

-doc "Check if the name is in a zone.".
-spec in_zone(binary()) -> boolean().
in_zone(Name) ->
    case find_zone_in_cache(Name) of
        {ok, Zone} ->
            is_name_in_zone(Name, Zone);
        _ ->
            false
    end.

-doc "Check if the record name is in the zone. Will also return true if a wildcard is present at the node.".
-spec record_name_in_zone(binary(), dns:dname()) -> boolean().
record_name_in_zone(ZoneName, Name) ->
    case find_zone_in_cache(Name) of
        {ok, Zone} ->
            case
                lists:flatten(
                    ets:select(
                        zone_records_typed,
                        [{{{ZoneName, erldns:normalize_name(Name), '_'}, '$1'}, [], ['$$']}]
                    )
                )
            of
                [] ->
                    is_name_in_zone_with_wildcard(Name, Zone);
                _ ->
                    true
            end;
        _ ->
            false
    end.

-doc "Return a list of tuples with each tuple as a name and the version SHA for the zone.".
-spec zone_names_and_versions() -> [{dns:dname(), binary()}].
zone_names_and_versions() ->
    ets:foldl(
        fun({_, Zone}, NamesAndShas) ->
            NamesAndShas ++ [{Zone#zone.name, Zone#zone.version}]
        end,
        [],
        zones
    ).

-doc "Return current sync counter".
-spec get_rrset_sync_counter(dns:dname(), dns:dname(), dns:type()) -> integer().
get_rrset_sync_counter(ZoneName, RRFqdn, Type) ->
    case
        ets:select(
            sync_counters,
            [
                {{erldns:normalize_name(ZoneName), erldns:normalize_name(RRFqdn), Type, '$1'}, [], [
                    '$_'
                ]}
            ]
        )
    of
        [{ZoneName, RRFqdn, Type, Counter}] ->
            Counter;
        [] ->
            % return default value of 0
            0
    end.

-doc "Update the RRSet sync counter for the given RR set name and type in the given zone.".
-spec write_rrset_sync_counter({dns:dname(), dns:dname(), dns:type(), integer()}) -> ok.
write_rrset_sync_counter({ZoneName, RRFqdn, Type, Counter}) ->
    true = ets:insert(sync_counters, {ZoneName, RRFqdn, Type, Counter}),
    ok.

% ----------------------------------------------------------------------------------------------------
% Write API

-doc """
Put a name and its records into the cache, along with a SHA which can be
used to determine if the zone requires updating.

This function will build the necessary Zone record before inserting.
""".
-spec put_zone({Name, Sha, Records, Keys} | {Name, Sha, Records}) -> ok when
    Name :: binary(),
    Sha :: binary(),
    Records :: [dns:rr()],
    Keys :: [erldns:keyset()].
put_zone({Name, Sha, Records}) ->
    put_zone({Name, Sha, Records, []});
put_zone({Name, Sha, Records, Keys}) ->
    SignedZone = sign_zone(build_zone(Name, Sha, Records, Keys)),
    NamedRecords = build_named_index(SignedZone#zone.records),
    delete_zone_records(erldns:normalize_name(Name)),
    true = put_zone(erldns:normalize_name(Name), SignedZone#zone{records = trimmed}),
    put_zone_records(erldns:normalize_name(Name), NamedRecords).

-doc "Put a zone into the cache and wait for a response.".
-spec put_zone(dns:dname(), erldns:zone()) -> true.
put_zone(Name, Zone) ->
    ets:insert(zones, {erldns:normalize_name(Name), Zone}).

-spec put_zone_records(dns:dname(), map()) -> ok.
put_zone_records(Name, RecordsByName) ->
    put_zone_records_entry(Name, maps:next(maps:iterator(RecordsByName))).

-doc "Put zone RRSet".
-spec put_zone_rrset(
    {dns:dname(), binary(), [dns:rr()]} | {dns:dname(), binary(), [dns:rr()], [any()]},
    dns:dname(),
    dns:type(),
    integer()
) ->
    ok | {error, Reason :: term()}.
put_zone_rrset({ZoneName, Digest, Records}, RRFqdn, Type, Counter) ->
    put_zone_rrset({ZoneName, Digest, Records, []}, RRFqdn, Type, Counter);
put_zone_rrset({ZoneName, Digest, Records, _Keys}, RRFqdn, Type, Counter) ->
    case find_zone_in_cache(erldns:normalize_name(ZoneName)) of
        {ok, Zone} ->
            % TODO: remove debug
            ?LOG_DEBUG("Putting RRSet (~p) with Type: ~p for Zone (~p): ~p", [
                RRFqdn, Type, ZoneName, Records
            ]),
            KeySets = Zone#zone.keysets,
            SignedRRSet = sign_rrset(ZoneName, Records, KeySets),
            {RRSigRecsCovering, RRSigRecsNotCovering} = filter_rrsig_records_with_type_covered(
                RRFqdn, Type
            ),
            % RRSet records + RRSIG records for the type + the rest of RRSIG records for FQDN
            TypedRecords = build_typed_index(Records ++ SignedRRSet ++ RRSigRecsNotCovering),
            CurrentRRSetRecords = get_records_by_name_and_type(RRFqdn, Type),
            ZoneRecordsCount = Zone#zone.record_count,
            % put zone_records_typed records first then create the records in zone_records
            put_zone_records_typed_entry(ZoneName, RRFqdn, maps:next(maps:iterator(TypedRecords))),

            UpdatedZoneRecordsCount =
                ZoneRecordsCount +
                    (length(Records) - length(CurrentRRSetRecords)) +
                    (length(SignedRRSet) - length(RRSigRecsCovering)),
            update_zone_records_and_digest(ZoneName, UpdatedZoneRecordsCount, Digest),
            write_rrset_sync_counter({ZoneName, RRFqdn, Type, Counter}),

            ?LOG_DEBUG("RRSet update completed for FQDN: ~p, Type: ~p", [RRFqdn, Type]),
            ok;
        % if zone is not in cache, return error
        _ ->
            {error, zone_not_found}
    end.

put_zone_records_entry(_, none) ->
    ok;
put_zone_records_entry(Name, {K, V, I}) ->
    put_zone_records_typed_entry(Name, K, maps:next(maps:iterator(build_typed_index(V)))),
    put_zone_records_entry(Name, maps:next(I)).

put_zone_records_typed_entry(_, _, none) ->
    ok;
put_zone_records_typed_entry(ZoneName, Fqdn, {K, V, I}) ->
    ets:insert(zone_records_typed, {
        {erldns:normalize_name(ZoneName), erldns:normalize_name(Fqdn), K}, V
    }),
    put_zone_records_typed_entry(ZoneName, Fqdn, maps:next(I)).

-doc "Remove a zone from the cache without waiting for a response.".
-spec delete_zone(binary()) -> any().
delete_zone(Name) ->
    ets:delete(zones, erldns:normalize_name(Name)),
    delete_zone_records(Name).

-spec delete_zone_records(binary()) -> any().
delete_zone_records(Name) ->
    ets:select_delete(zone_records_typed, [
        {{{erldns:normalize_name(Name), '_', '_'}, '_'}, [], [true]}
    ]).

-doc "Remove zone RRSet".
-spec delete_zone_rrset(binary(), binary(), binary(), integer(), integer()) -> any().
delete_zone_rrset(ZoneName, Digest, RRFqdn, Type, Counter) ->
    case find_zone_in_cache(erldns:normalize_name(ZoneName)) of
        {ok, Zone} ->
            Zone,
            CurrentCounter = get_rrset_sync_counter(ZoneName, RRFqdn, Type),
            case Counter of
                N when N =:= 0; CurrentCounter < N ->
                    ?LOG_DEBUG("Removing RRSet (~p) with type ~p", [RRFqdn, Type]),
                    ZoneRecordsCount = Zone#zone.record_count,
                    CurrentRRSetRecords = get_records_by_name_and_type(RRFqdn, Type),
                    ets:select_delete(
                        zone_records_typed,
                        [
                            {
                                {
                                    {
                                        erldns:normalize_name(ZoneName),
                                        erldns:normalize_name(RRFqdn),
                                        Type
                                    },
                                    '_'
                                },
                                [],
                                [true]
                            }
                        ]
                    ),

                    % remove the RRSIG for the given record type
                    {RRSigsCovering, RRSigsNotCovering} =
                        lists:partition(
                            erldns_records:match_type_covered(Type),
                            get_records_by_name_and_type(RRFqdn, ?DNS_TYPE_RRSIG_NUMBER)
                        ),
                    ets:insert(
                        zone_records_typed,
                        {
                            {
                                erldns:normalize_name(ZoneName),
                                erldns:normalize_name(RRFqdn),
                                ?DNS_TYPE_RRSIG_NUMBER
                            },
                            RRSigsNotCovering
                        }
                    ),

                    % only write counter if called explicitly with Counter value i.e. different than 0.
                    % this will not write the counter if called by put_zone_rrset/3 as it will prevent subsequent delete ops
                    case Counter of
                        N when N > 0 ->
                            % DELETE RRSet command has been sent
                            % we need to update the zone digest as the zone content changes
                            UpdatedZoneRecordsCount =
                                ZoneRecordsCount -
                                    length(CurrentRRSetRecords) -
                                    length(RRSigsCovering),
                            update_zone_records_and_digest(
                                ZoneName, UpdatedZoneRecordsCount, Digest
                            ),
                            write_rrset_sync_counter({ZoneName, RRFqdn, Type, Counter});
                        _ ->
                            ok
                    end;
                N when CurrentCounter > N ->
                    ?LOG_DEBUG(
                        "Not processing delete operation for RRSet (~p): counter (~p) provided is lower than system",
                        [
                            RRFqdn, Counter
                        ]
                    )
            end;
        _ ->
            {error, zone_not_found}
    end.

-doc "Given a zone name, list of records, and a digest, update the zone metadata in cache.".
-spec update_zone_records_and_digest(dns:dname(), integer(), binary()) ->
    ok | {error, Reason :: term()}.
update_zone_records_and_digest(ZoneName, RecordsCount, Digest) ->
    case find_zone_in_cache(erldns:normalize_name(ZoneName)) of
        {ok, Zone} ->
            Zone,
            UpdatedZone =
                Zone#zone{
                    version = Digest,
                    authority = get_records_by_name_and_type(ZoneName, ?DNS_TYPE_SOA),
                    record_count = RecordsCount
                },
            put_zone(Zone#zone.name, UpdatedZone);
        _ ->
            {error, zone_not_found}
    end.

-doc "Filter RRSig records for FQDN, removing type covered.".
-spec filter_rrsig_records_with_type_covered(dns:dname(), dns:type()) ->
    {[dns:rr()], [dns:rr()]} | {[], []}.
filter_rrsig_records_with_type_covered(RRFqdn, TypeCovered) ->
    % guards below do not allow fun calls to prevent side effects
    case find_zone_in_cache(erldns:normalize_name(RRFqdn)) of
        {ok, _Zone} ->
            % {RRSigsCovering, RRSigsNotCovering} =
            lists:partition(
                erldns_records:match_type_covered(TypeCovered),
                get_records_by_name_and_type(RRFqdn, ?DNS_TYPE_RRSIG_NUMBER)
            );
        _ ->
            {[], []}
    end.

% Internal API
is_name_in_zone(Name, Zone) ->
    ZoneName = erldns:normalize_name(Zone#zone.name),
    case
        lists:flatten(
            ets:select(
                zone_records_typed,
                [{{{ZoneName, erldns:normalize_name(Name), '_'}, '$1'}, [], ['$$']}]
            )
        )
    of
        [] ->
            case dns:dname_to_labels(Name) of
                [] ->
                    false;
                [_] ->
                    false;
                [_ | Labels] ->
                    is_name_in_zone(dns:labels_to_dname(Labels), Zone)
            end;
        _ ->
            true
    end.

is_name_in_zone_with_wildcard(Name, Zone) ->
    ZoneName = erldns:normalize_name(Zone#zone.name),
    WildcardName = erldns:normalize_name(erldns_records:wildcard_qname(Name)),
    case
        lists:flatten(
            ets:select(
                zone_records_typed, [{{{ZoneName, WildcardName, '_'}, '$1'}, [], ['$$']}]
            )
        )
    of
        [] ->
            case dns:dname_to_labels(Name) of
                [] ->
                    false;
                [_] ->
                    false;
                [_ | Labels] ->
                    is_name_in_zone_with_wildcard(dns:labels_to_dname(Labels), Zone)
            end;
        _ ->
            true
    end.

find_zone_in_cache(Qname) ->
    Name = erldns:normalize_name(Qname),
    find_zone_in_cache(Name, dns:dname_to_labels(Name)).

find_zone_in_cache(_Name, []) ->
    {error, zone_not_found};
find_zone_in_cache(Name, [_ | Labels]) ->
    case ets:lookup(zones, Name) of
        [{Name, Zone}] ->
            {ok, Zone};
        _ ->
            case Labels of
                [] ->
                    {error, zone_not_found};
                _ ->
                    find_zone_in_cache(dns:labels_to_dname(Labels))
            end
    end.

build_zone(Qname, Version, Records, Keys) ->
    Authorities = lists:filter(erldns_records:match_type(?DNS_TYPE_SOA), Records),
    #zone{
        name = Qname,
        version = Version,
        record_count = length(Records),
        authority = Authorities,
        records = Records,
        records_by_name = trimmed,
        keysets = Keys
    }.

-spec build_named_index([dns:rr()]) -> #{binary() => [dns:rr()]}.
build_named_index(Records) ->
    NamedIndex =
        lists:foldl(
            fun(R, Idx) ->
                Name = erldns:normalize_name(R#dns_rr.name),
                maps:update_with(Name, fun(RR) -> [R | RR] end, [R], Idx)
            end,
            #{},
            Records
        ),
    maps:map(fun(_K, V) -> lists:reverse(V) end, NamedIndex).

-spec build_typed_index([dns:rr()]) -> #{dns:type() => [dns:rr()]}.
build_typed_index(Records) ->
    TypedIndex = lists:foldl(
        fun(R, Idx) -> maps:update_with(R#dns_rr.type, fun(RR) -> [R | RR] end, [R], Idx) end,
        #{},
        Records
    ),
    maps:map(fun(_K, V) -> lists:reverse(V) end, TypedIndex).

-spec sign_zone(erldns:zone()) -> erldns:zone().
sign_zone(Zone = #zone{keysets = []}) ->
    Zone;
sign_zone(Zone) ->
    DnskeyRRs = lists:filter(erldns_records:match_type(?DNS_TYPE_DNSKEY), Zone#zone.records),
    KeyRRSigRecords = lists:flatten(
        lists:map(erldns_dnssec:key_rrset_signer(Zone#zone.name, DnskeyRRs), Zone#zone.keysets)
    ),
    % TODO: remove wildcard signatures as they will not be used but are taking up space
    ZoneRRSigRecords =
        lists:flatten(
            lists:map(
                erldns_dnssec:zone_rrset_signer(
                    Zone#zone.name,
                    lists:filter(
                        fun(RR) -> RR#dns_rr.type =/= ?DNS_TYPE_DNSKEY end, Zone#zone.records
                    )
                ),
                Zone#zone.keysets
            )
        ),
    Records =
        Zone#zone.records ++
            KeyRRSigRecords ++
            rewrite_soa_rrsig_ttl(
                Zone#zone.records,
                ZoneRRSigRecords -- lists:filter(erldns_records:match_wildcard(), ZoneRRSigRecords)
            ),
    #zone{
        name = Zone#zone.name,
        version = Zone#zone.version,
        record_count = length(Records),
        authority = Zone#zone.authority,
        records = Records,
        records_by_name = build_named_index(Records),
        keysets = Zone#zone.keysets
    }.

% Sign RRSet
-spec sign_rrset(binary(), [dns:rr()], [erldns:keyset()]) -> [dns:rr()].
sign_rrset(Name, Records, KeySets) ->
    ZoneRecords = get_records_by_name_and_type(Name, ?DNS_TYPE_SOA),
    RRSigRecords =
        rewrite_soa_rrsig_ttl(
            ZoneRecords,
            lists:flatten(
                lists:map(
                    erldns_dnssec:zone_rrset_signer(
                        Name,
                        lists:filter(
                            fun(RR) -> RR#dns_rr.type =/= ?DNS_TYPE_DNSKEY end,
                            Records
                        )
                    ),
                    KeySets
                )
            )
        ),
    RRSigRecords.

% Rewrite the RRSIG TTL so it follows the same rewrite rules as the SOA TTL.
rewrite_soa_rrsig_ttl(ZoneRecords, RRSigRecords) ->
    SoaRR = lists:last(lists:filter(erldns_records:match_type(?DNS_TYPE_SOA), ZoneRecords)),
    lists:map(
        fun(RR) ->
            case RR#dns_rr.type of
                ?DNS_TYPE_RRSIG ->
                    case RR#dns_rr.data#dns_rrdata_rrsig.type_covered of
                        ?DNS_TYPE_SOA -> erldns_records:minimum_soa_ttl(RR, SoaRR#dns_rr.data);
                        _ -> RR
                    end;
                _ ->
                    RR
            end
        end,
        RRSigRecords
    ).

-doc false.
-spec start_link() -> any().
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, noargs, [{hibernate_after, 0}]).

-doc false.
-spec init(noargs) -> {ok, nostate}.
init(noargs) ->
    create(zones),
    create(zone_records_typed),
    create(sync_counters),
    {ok, nostate}.

-doc false.
-spec handle_call(dynamic(), gen_server:from(), nostate) ->
    {reply, not_implemented, nostate}.
handle_call(Call, From, State) ->
    ?LOG_INFO(#{what => unexpected_call, from => From, call => Call}),
    {reply, not_implemented, State}.

-doc false.
-spec handle_cast(dynamic(), nostate) -> {noreply, nostate}.
handle_cast(Cast, State) ->
    ?LOG_INFO(#{what => unexpected_cast, cast => Cast}),
    {noreply, State}.

-spec create_ets_table(atom(), ets:table_type()) -> ok | {error, term()}.
create_ets_table(Name, Type) ->
    case ets:info(Name) of
        undefined ->
            Name = ets:new(Name, [Type, public, named_table]),
            ok;
        _InfoList ->
            ok
    end.
