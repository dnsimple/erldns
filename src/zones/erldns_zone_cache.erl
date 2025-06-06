-module(erldns_zone_cache).
-moduledoc """
A cache holding all of the zone data.

Write operations occur through the cache process mailbox, whereas read
operations occur directly through the underlying data store.

Supports only a single question per request: if a request contains multiple questions,
only the first question will be resolved.
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

-export([
    put_zone/1,
    delete_zone/1,
    update_zone_records_and_digest/3,
    put_zone_rrset/4,
    delete_zone_rrset/5
]).

-export([create/1]).

-export([start_link/0, init/1, handle_call/3, handle_cast/2]).

-doc "Creates a new table.".
-spec create(atom()) -> ok | {error, Reason :: term()}.
create(zones) ->
    create_ets_table(zones, set, #zone.name);
create(zone_records_typed) ->
    create_ets_table(zone_records_typed, ordered_set);
create(sync_counters) ->
    create_ets_table(sync_counters, set).

-doc "Find a zone for a given qname.".
-spec find_zone(dns:dname()) ->
    erldns:zone() | {error, no_question | zone_not_found | not_authoritative}.
find_zone(Name) ->
    case get_authority(Name) of
        {error, Error} ->
            {error, Error};
        {ok, Authority} ->
            find_zone(Name, Authority)
    end.

-doc "Find a zone for a given qname.".
-spec find_zone(dns:dname(), dns:rr() | [dns:rr()]) ->
    erldns:zone() | {error, zone_not_found | not_authoritative}.
find_zone(_Name, []) ->
    {error, not_authoritative};
find_zone(Name, [FirstAuthority | _]) ->
    find_zone(Name, FirstAuthority);
find_zone(Name, #dns_rr{} = Authority) ->
    NormalizedName = dns:dname_to_lower(Name),
    case dns:dname_to_labels(NormalizedName) of
        [_ | Labels] ->
            case get_zone(NormalizedName) of
                #zone{} = Zone ->
                    Zone;
                {error, zone_not_found} ->
                    case NormalizedName =:= Authority#dns_rr.name of
                        true ->
                            {error, zone_not_found};
                        false ->
                            find_zone(dns:labels_to_dname(Labels), Authority)
                    end
            end;
        _ ->
            {error, zone_not_found}
    end.

-doc """
Get a zone for the specific name.

This function will not attempt to resolve the dname in any way,
it will simply look up the name in the underlying data store.
""".
-spec get_zone(dns:dname()) -> erldns:zone() | {error, zone_not_found}.
get_zone(Name) ->
    NormalizedName = dns:dname_to_lower(Name),
    case ets:lookup(zones, NormalizedName) of
        [] ->
            {error, zone_not_found};
        [#zone{} = Zone] ->
            Zone#zone{records = []}
    end.

-doc "Find the SOA record for the given DNS question or zone.".
-spec get_authority(dns:message() | dns:dname()) ->
    {error, no_question} | {error, not_authoritative} | {ok, dns:authority()}.
get_authority(#dns_message{questions = []}) ->
    {error, no_question};
get_authority(#dns_message{questions = [Question | _]}) ->
    get_authority(Question#dns_query.name);
get_authority(Name) when is_binary(Name) ->
    NormalizedName = dns:dname_to_lower(Name),
    case find_zone_in_cache(NormalizedName, #zone.authority) of
        zone_not_found ->
            {error, not_authoritative};
        Authority ->
            {ok, Authority}
    end.

-doc """
Get the list of NS and glue records for the given name.

This function will always return a list, even if it is empty.
""".
-spec get_delegations(dns:dname()) -> [dns:rr()].
get_delegations(Name) ->
    NormalizedName = dns:dname_to_lower(Name),
    case find_zone_in_cache(NormalizedName, #zone.name) of
        zone_not_found ->
            [];
        ZoneName ->
            NormalizedZoneName = dns:dname_to_lower(ZoneName),
            Pattern = {{{NormalizedZoneName, NormalizedName, ?DNS_TYPE_NS}, '$1'}, [], ['$1']},
            Records = lists:append(ets:select(zone_records_typed, [Pattern])),
            lists:filter(erldns_records:match_delegation(NormalizedName), Records)
    end.

-doc "Get all records for the given zone.".
-spec get_zone_records(dns:dname()) -> [dns:rr()].
get_zone_records(Name) ->
    NormalizedName = dns:dname_to_lower(Name),
    case find_zone_in_cache(NormalizedName, #zone.name) of
        zone_not_found ->
            [];
        ZoneName ->
            NormalizedZoneName = dns:dname_to_lower(ZoneName),
            Pattern = {{{NormalizedZoneName, '_', '_'}, '$1'}, [], ['$1']},
            lists:append(ets:select(zone_records_typed, [Pattern]))
    end.

-doc "Get all records for the given type and given name.".
-spec get_records_by_name_and_type(dns:dname(), dns:type()) -> [dns:rr()].
get_records_by_name_and_type(Name, Type) ->
    NormalizedName = dns:dname_to_lower(Name),
    case find_zone_in_cache(NormalizedName, #zone.name) of
        zone_not_found ->
            [];
        ZoneName ->
            NormalizedZoneName = dns:dname_to_lower(ZoneName),
            Pattern = {{{NormalizedZoneName, NormalizedName, Type}, '$1'}, [], ['$1']},
            lists:append(ets:select(zone_records_typed, [Pattern]))
    end.

-doc "Return the record set for the given dname.".
-spec get_records_by_name(dns:dname()) -> [dns:rr()].
get_records_by_name(Name) ->
    NormalizedName = dns:dname_to_lower(Name),
    case find_zone_in_cache(NormalizedName, #zone.name) of
        zone_not_found ->
            [];
        ZoneName ->
            NormalizedZoneName = dns:dname_to_lower(ZoneName),
            Pattern = {{{NormalizedZoneName, NormalizedName, '_'}, '$1'}, [], ['$1']},
            lists:append(ets:select(zone_records_typed, [Pattern]))
    end.

-doc "Check if the name is in a zone.".
-spec in_zone(binary()) -> boolean().
in_zone(Name) ->
    NormalizedName = dns:dname_to_lower(Name),
    case find_zone_in_cache(NormalizedName, #zone.name) of
        zone_not_found ->
            false;
        ZoneName ->
            is_name_in_zone(NormalizedName, ZoneName)
    end.

-doc """
Check if the record name is in the zone.

Will also return true if a wildcard is present at the node.
""".
-spec record_name_in_zone(binary(), dns:dname()) -> boolean().
record_name_in_zone(ZoneName, Name) ->
    NormalizedName = dns:dname_to_lower(Name),
    NormalizedZoneName = dns:dname_to_lower(ZoneName),
    case find_zone_in_cache(NormalizedName, #zone.name) of
        zone_not_found ->
            false;
        ZoneName ->
            Pattern = {{{NormalizedZoneName, NormalizedName, '_'}, '_'}, [], [true]},
            case ets:select_count(zone_records_typed, [Pattern]) of
                0 ->
                    is_name_in_zone_with_wildcard(NormalizedName, ZoneName);
                _ ->
                    true
            end
    end.

-doc "Return a list of tuples with each tuple as a name and the version SHA for the zone.".
-spec zone_names_and_versions() -> [{dns:dname(), binary()}].
zone_names_and_versions() ->
    ets:foldl(
        fun(Zone, NamesAndShas) ->
            [{Zone#zone.name, Zone#zone.version} | NamesAndShas]
        end,
        [],
        zones
    ).

-doc "Return current sync counter".
-spec get_rrset_sync_counter(dns:dname(), dns:dname(), dns:type()) -> integer().
get_rrset_sync_counter(ZoneName, RRFqdn, Type) ->
    NormalizedZoneName = dns:dname_to_lower(ZoneName),
    NormalizedRRFqdn = dns:dname_to_lower(RRFqdn),
    Key = {NormalizedZoneName, NormalizedRRFqdn, Type},
    % return default value of 0
    ets:lookup_element(sync_counters, Key, 2, 0).

%% Update the RRSet sync counter for the given RR set name and type in the given zone.
-spec write_rrset_sync_counter(dns:dname(), dns:dname(), dns:type(), integer()) -> ok.
write_rrset_sync_counter(ZoneName, RRFqdn, Type, Counter) ->
    true = ets:insert(sync_counters, {{ZoneName, RRFqdn, Type}, Counter}),
    ok.

% ----------------------------------------------------------------------------------------------------
% Write API
%% All write operations write records with normalized names, hence reads won't need to
%% renormalize again and again

-doc """
Put a name and its records into the cache, along with a SHA which can be
used to determine if the zone requires updating.

This function will build the necessary Zone record before inserting.

The name of each record must be the fully qualified domain name (including the zone part).

Here's an example:

```erlang
erldns_zone_cache:put_zone({
  <<"example.com">>, <<"someDigest">>, [
    #dns_rr{
      name = <<"example.com">>,
      type = ?DNS_TYPE_A,
      ttl = 3600,
      data = #dns_rrdata_a{ip = {1,2,3,4}}
    },
    #dns_rr{
      name = <<"www.example.com">>,
      type = ?DNS_TYPE_CNAME,
      ttl = 3600,
      data = #dns_rrdata_cname{dname = <<"example.com">>}
    }
  ]}).
```
""".
-spec put_zone(Zone | {Name, Sha, Records} | {Name, Sha, Records, Keys}) -> ok when
    Zone :: erldns:zone(),
    Name :: dns:dname(),
    Sha :: binary(),
    Records :: [dns:rr()],
    Keys :: [erldns:keyset()].
put_zone({Name, Sha, Records}) ->
    put_zone({Name, Sha, Records, []});
put_zone({Name, Sha, Records, Keys}) ->
    NormalizedName = dns:dname_to_lower(Name),
    put_zone(build_zone(NormalizedName, Sha, Records, Keys));
put_zone(#zone{name = Name} = Zone) ->
    NormalizedName = dns:dname_to_lower(Name),
    SignedZone = sign_zone(Zone#zone{name = NormalizedName}),
    NamedRecords = build_named_index(SignedZone#zone.records),
    ZoneRecords = prepare_zone_records(NormalizedName, NamedRecords),
    delete_zone_records(NormalizedName),
    true = insert_zone(SignedZone#zone{records = trimmed}),
    put_zone_records(ZoneRecords).

-doc "Put zone RRSet".
-spec put_zone_rrset(RRSet, RRFqdn, Type, Counter) -> ok | {error, term()} when
    RRSet :: {dns:dname(), binary(), [dns:rr()]} | {dns:dname(), binary(), [dns:rr()], [term()]},
    RRFqdn :: dns:dname(),
    Type :: dns:type(),
    Counter :: integer().
put_zone_rrset({ZoneName, Digest, Records}, RRFqdn, Type, Counter) ->
    put_zone_rrset({ZoneName, Digest, Records, []}, RRFqdn, Type, Counter);
put_zone_rrset({ZoneName, Digest, Records, _Keys}, RRFqdn, Type, Counter) ->
    NormalizedZoneName = dns:dname_to_lower(ZoneName),
    case find_zone_in_cache(NormalizedZoneName, zone) of
        #zone{} = Zone ->
            ?LOG_DEBUG(#{
                what => putting_rrset,
                rrset => RRFqdn,
                type => Type,
                zone => NormalizedZoneName,
                records => Records
            }),
            KeySets = Zone#zone.keysets,
            SignedRRSet = sign_rrset(NormalizedZoneName, Records, KeySets),
            {RRSigRecsCovering, RRSigRecsNotCovering} = filter_rrsig_records_with_type_covered(
                RRFqdn, Type
            ),
            % RRSet records + RRSIG records for the type + the rest of RRSIG records for FQDN
            CurrentRRSetRecords = get_records_by_name_and_type(RRFqdn, Type),
            ZoneRecordsCount = Zone#zone.record_count,
            % put zone_records_typed records first then create the records in zone_records
            TypedRecords = Records ++ SignedRRSet ++ RRSigRecsNotCovering,
            put_zone_records_typed_entry(NormalizedZoneName, RRFqdn, TypedRecords),
            UpdatedZoneRecordsCount =
                ZoneRecordsCount +
                    (length(Records) - length(CurrentRRSetRecords)) +
                    (length(SignedRRSet) - length(RRSigRecsCovering)),
            update_zone_records_and_digest(ZoneName, UpdatedZoneRecordsCount, Digest),
            write_rrset_sync_counter(NormalizedZoneName, RRFqdn, Type, Counter),
            ?LOG_DEBUG(#{
                what => rrset_update_completed,
                rrset => RRFqdn,
                type => Type
            });
        % if zone is not in cache, return error
        zone_not_found ->
            {error, zone_not_found}
    end.

-doc "Remove a zone from the cache without waiting for a response.".
-spec delete_zone(dns:dname()) -> term().
delete_zone(Name) ->
    NormalizedName = dns:dname_to_lower(Name),
    ets:delete(zones, NormalizedName),
    delete_zone_records(NormalizedName).

%% Expects normalized names
-spec delete_zone_records(dns:dname()) -> term().
delete_zone_records(NormalizedName) ->
    Pattern = {{{NormalizedName, '_', '_'}, '_'}, [], [true]},
    ets:select_delete(zone_records_typed, [Pattern]).

-doc "Remove zone RRSet".
-spec delete_zone_rrset(binary(), binary(), binary(), integer(), integer()) -> term().
delete_zone_rrset(ZoneName, Digest, RRFqdn, Type, Counter) ->
    NormalizedZoneName = dns:dname_to_lower(ZoneName),
    case find_zone_in_cache(NormalizedZoneName, zone) of
        #zone{} = Zone ->
            CurrentCounter = get_rrset_sync_counter(ZoneName, RRFqdn, Type),
            case Counter of
                N when N =:= 0; CurrentCounter < N ->
                    ?LOG_DEBUG(#{
                        what => removing_rrset,
                        rrset => RRFqdn,
                        type => Type
                    }),
                    ZoneRecordsCount = Zone#zone.record_count,
                    CurrentRRSetRecords = get_records_by_name_and_type(RRFqdn, Type),
                    NormalizedRRFqdn = dns:dname_to_lower(RRFqdn),
                    Pattern = {{{NormalizedZoneName, NormalizedRRFqdn, Type}, '_'}, [], [true]},
                    ets:select_delete(zone_records_typed, [Pattern]),
                    % remove the RRSIG for the given record type
                    {RRSigsCovering, RRSigsNotCovering} =
                        lists:partition(
                            erldns_records:match_type_covered(Type),
                            get_records_by_name_and_type(RRFqdn, ?DNS_TYPE_RRSIG_NUMBER)
                        ),
                    Value = {
                        {NormalizedZoneName, NormalizedRRFqdn, ?DNS_TYPE_RRSIG_NUMBER},
                        RRSigsNotCovering
                    },
                    ets:insert(zone_records_typed, Value),
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
                            write_rrset_sync_counter(NormalizedZoneName, RRFqdn, Type, Counter);
                        _ ->
                            ok
                    end;
                N when CurrentCounter > N ->
                    ?LOG_DEBUG(#{
                        what => not_processing_delete_rrset,
                        reason => counter_lower_than_system,
                        rrset => RRFqdn,
                        counter => Counter
                    })
            end;
        zone_not_found ->
            {error, zone_not_found}
    end.

-doc "Given a zone name, list of records, and a digest, update the zone metadata in cache.".
-spec update_zone_records_and_digest(dns:dname(), integer(), binary()) ->
    ok | {error, Reason :: term()}.
update_zone_records_and_digest(ZoneName, RecordsCount, Digest) ->
    NormalizedZoneName = dns:dname_to_lower(ZoneName),
    case find_zone_in_cache(NormalizedZoneName, zone) of
        #zone{} = Zone ->
            UpdatedZone =
                Zone#zone{
                    version = Digest,
                    authority = get_records_by_name_and_type(ZoneName, ?DNS_TYPE_SOA),
                    record_count = RecordsCount
                },
            true = insert_zone(UpdatedZone),
            ok;
        zone_not_found ->
            {error, zone_not_found}
    end.

%% Filter RRSig records for FQDN, removing type covered..
-spec filter_rrsig_records_with_type_covered(dns:dname(), dns:type()) ->
    {[dns:rr()], [dns:rr()]} | {[], []}.
filter_rrsig_records_with_type_covered(RRFqdn, TypeCovered) ->
    % guards below do not allow fun calls to prevent side effects
    NormalizedRRFqdn = dns:dname_to_lower(RRFqdn),
    case find_zone_in_cache(NormalizedRRFqdn, member) of
        true ->
            % {RRSigsCovering, RRSigsNotCovering} =
            lists:partition(
                erldns_records:match_type_covered(TypeCovered),
                get_records_by_name_and_type(RRFqdn, ?DNS_TYPE_RRSIG_NUMBER)
            );
        zone_not_found ->
            {[], []}
    end.

% Internal API
-spec insert_zone(erldns:zone()) -> true.
insert_zone(#zone{} = Zone) ->
    ets:insert(zones, Zone).

%% expects name to be already normalized
-spec prepare_zone_records(dns:dname(), map()) -> list().
prepare_zone_records(NormalizedName, RecordsByName) ->
    lists:flatmap(
        fun({Fqdn, Records}) ->
            NormalizedFqdn = dns:dname_to_lower(Fqdn),
            TypedRecords = build_typed_index(Records),
            ListTypedRecords = maps:to_list(TypedRecords),
            prepare_zone_records_typed_entry(NormalizedName, NormalizedFqdn, ListTypedRecords)
        end,
        maps:to_list(RecordsByName)
    ).

%% expects name to be already normalized
prepare_zone_records_typed_entry(NormalizedName, NormalizedFqdn, ListTypedRecords) ->
    lists:map(
        fun({Type, Record}) ->
            {{NormalizedName, NormalizedFqdn, Type}, Record}
        end,
        ListTypedRecords
    ).

%% expects name to be already normalized
-spec put_zone_records(list()) -> ok.
put_zone_records(RecordsByName) ->
    lists:foreach(
        fun(Entry) ->
            ets:insert(zone_records_typed, Entry)
        end,
        RecordsByName
    ).

%% expects name to be already normalized
put_zone_records_typed_entry(NormalizedName, Fqdn, Records) ->
    NormalizedFqdn = dns:dname_to_lower(Fqdn),
    TypedRecords = build_typed_index(Records),
    maps:foreach(
        fun(Type, Record) ->
            do_put_zone_records_typed_entry(NormalizedName, NormalizedFqdn, Type, Record)
        end,
        TypedRecords
    ).

do_put_zone_records_typed_entry(NormalizedName, NormalizedFqdn, Type, Record) ->
    ets:insert(zone_records_typed, {{NormalizedName, NormalizedFqdn, Type}, Record}).

%% expects name to be already normalized
is_name_in_zone(NormalizedName, NormalizedZoneName) ->
    Pattern = {{{NormalizedZoneName, NormalizedName, '_'}, '$1'}, [], ['$1']},
    case lists:append(ets:select(zone_records_typed, [Pattern])) of
        [] ->
            case dns:dname_to_labels(NormalizedName) of
                [] ->
                    false;
                [_] ->
                    false;
                [_ | Labels] ->
                    is_name_in_zone(dns:labels_to_dname(Labels), NormalizedZoneName)
            end;
        _ ->
            true
    end.

%% expects name to be already normalized
is_name_in_zone_with_wildcard(NormalizedName, NormalizedZoneName) ->
    WildcardName = dns:dname_to_lower(erldns_records:wildcard_qname(NormalizedName)),
    Pattern = {{{NormalizedZoneName, WildcardName, '_'}, '_'}, [], [true]},
    case ets:select_count(zone_records_typed, [Pattern]) of
        0 ->
            case dns:dname_to_labels(NormalizedName) of
                [] ->
                    false;
                [_] ->
                    false;
                [_ | Labels] ->
                    is_name_in_zone_with_wildcard(dns:labels_to_dname(Labels), NormalizedZoneName)
            end;
        _ ->
            true
    end.

%% expects name to be already normalized
-spec find_zone_in_cache
    (dns:dname(), zone) -> erldns:zone();
    (dns:dname(), member) -> boolean();
    (dns:dname(), dynamic()) -> dynamic().
find_zone_in_cache(Name, Pos) ->
    NormalizedName = dns:dname_to_lower(Name),
    find_zone_in_cache(NormalizedName, dns:dname_to_labels(NormalizedName), Pos).

find_zone_in_cache(_Name, [], _) ->
    zone_not_found;
find_zone_in_cache(Name, [_ | Labels], zone) ->
    case ets:lookup(zones, Name) of
        [] ->
            if_labels_find_zone_in_cache(Labels, zone);
        [#zone{} = Zone] ->
            Zone
    end;
find_zone_in_cache(Name, [_ | Labels], member) ->
    case ets:member(zones, Name) of
        false ->
            if_labels_find_zone_in_cache(Labels, member);
        true ->
            true
    end;
find_zone_in_cache(Name, [_ | Labels], Pos) ->
    case ets:lookup_element(zones, Name, Pos, zone_not_found) of
        zone_not_found ->
            if_labels_find_zone_in_cache(Labels, Pos);
        Elem ->
            Elem
    end.

if_labels_find_zone_in_cache([], _QueryType) ->
    zone_not_found;
if_labels_find_zone_in_cache(Labels, QueryType) ->
    find_zone_in_cache(dns:labels_to_dname(Labels), QueryType).

%% Expects normalized names
build_zone(NormalizedName, Version, Records, Keys) ->
    Authorities = lists:filter(erldns_records:match_type(?DNS_TYPE_SOA), Records),
    #zone{
        name = NormalizedName,
        version = Version,
        record_count = length(Records),
        authority = Authorities,
        records = Records,
        keysets = Keys
    }.

-spec build_named_index([dns:rr()]) -> #{binary() => [dns:rr()]}.
build_named_index(Records) ->
    maps:groups_from_list(fun(R) -> dns:dname_to_lower(R#dns_rr.name) end, Records).

-spec build_typed_index([dns:rr()]) -> #{dns:type() => [dns:rr()]}.
build_typed_index(Records) ->
    maps:groups_from_list(fun(R) -> R#dns_rr.type end, Records).

-spec sign_zone(erldns:zone()) -> erldns:zone().
sign_zone(Zone = #zone{keysets = []}) ->
    Zone;
sign_zone(Zone) ->
    DnskeyRRs = lists:filter(erldns_records:match_type(?DNS_TYPE_DNSKEY), Zone#zone.records),
    KeyRRSigRecords = lists:flatmap(
        erldns_dnssec:key_rrset_signer(Zone#zone.name, DnskeyRRs), Zone#zone.keysets
    ),
    % TODO: remove wildcard signatures as they will not be used but are taking up space
    ZoneRRSigRecords =
        lists:flatmap(
            erldns_dnssec:zone_rrset_signer(
                Zone#zone.name,
                lists:filter(
                    fun(RR) -> RR#dns_rr.type =/= ?DNS_TYPE_DNSKEY end, Zone#zone.records
                )
            ),
            Zone#zone.keysets
        ),
    Records =
        Zone#zone.records ++
            KeyRRSigRecords ++
            rewrite_soa_rrsig_ttl(
                Zone#zone.records,
                ZoneRRSigRecords -- lists:filter(erldns_records:match_wildcard(), ZoneRRSigRecords)
            ),
    Zone#zone{
        record_count = length(Records),
        records = Records
    }.

% Sign RRSet
%% Expects normalized names
-spec sign_rrset(binary(), [dns:rr()], [erldns:keyset()]) -> [dns:rr()].
sign_rrset(NormalizedZoneName, Records, KeySets) ->
    ZoneRecords = get_records_by_name_and_type(NormalizedZoneName, ?DNS_TYPE_SOA),
    RRSigRecords =
        rewrite_soa_rrsig_ttl(
            ZoneRecords,
            lists:flatmap(
                erldns_dnssec:zone_rrset_signer(
                    NormalizedZoneName,
                    lists:filter(
                        fun(RR) -> RR#dns_rr.type =/= ?DNS_TYPE_DNSKEY end,
                        Records
                    )
                ),
                KeySets
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
-spec start_link() -> term().
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
create_ets_table(TableName, Type) ->
    create_ets_table(TableName, Type, 1).

-spec create_ets_table(atom(), ets:table_type(), non_neg_integer()) -> ok | {error, term()}.
create_ets_table(TableName, Type, Pos) ->
    case ets:info(TableName) of
        undefined ->
            Opts = [
                Type,
                public,
                named_table,
                {keypos, Pos},
                {read_concurrency, true},
                {write_concurrency, auto},
                {decentralized_counters, true}
            ],
            TableName = ets:new(TableName, Opts),
            ok;
        _InfoList ->
            ok
    end.
