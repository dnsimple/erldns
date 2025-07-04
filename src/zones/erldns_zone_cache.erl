-module(erldns_zone_cache).
-moduledoc """
A cache holding all of the zone data.

This module holds three tables:
- `zones`: holds the zones themselves, with their keysets and authority records.
- `zone_records_typed`: holds all RR records, namespaced by their parent zone and `t:dns:type/0`.
- `sync_counters`: holds a counter of updates for each RR.
""".

-behaviour(gen_server).

-include_lib("dns_erlang/include/dns.hrl").
-include_lib("kernel/include/logger.hrl").
-include_lib("erldns/include/erldns.hrl").

-define(LOG_METADATA, #{domain => [erldns, zones]}).

-export([
    lookup_zone/1,
    get_zone_records/1,
    get_records_by_name/1,
    get_records_by_name/2,
    get_records_by_name_wildcard/2,
    get_records_by_name_ent/2,
    get_records_by_name_and_type/2,
    get_records_by_name_and_type/3,
    get_authoritative_zone/1,
    get_delegations/1,
    get_rrset_sync_counter/3,
    is_in_any_zone/1,
    is_record_name_in_zone/2,
    is_record_name_in_zone_strict/2
]).

%% Other
-export([
    create/1,
    zone_names_and_versions/0,
    put_zone/1,
    delete_zone/1,
    update_zone_records_and_digest/3,
    put_zone_rrset/4,
    delete_zone_rrset/5
]).

-export([start_link/0, init/1, handle_call/3, handle_cast/2]).

-doc #{group => ~"API: Lookups"}.
-doc """
Get a zone for the specific name.

This function will not attempt to resolve the dname in any way,
it will simply look up the name in the underlying data store.
""".
-spec lookup_zone(dns:dname() | [dns:label()]) -> erldns:zone() | zone_not_found.
lookup_zone(Name) when is_binary(Name) ->
    Labels = dns:dname_to_lower_labels(Name),
    lookup_zone(Labels);
lookup_zone(Labels) when is_list(Labels) ->
    case ets:lookup(zones, Labels) of
        [] ->
            zone_not_found;
        [#zone{} = Zone] ->
            Zone
    end.

-doc #{group => ~"API: Lookups"}.
-doc "Get all records for the given zone.".
-spec get_zone_records(erldns:zone() | dns:dname() | [dns:label()]) -> [dns:rr()].
get_zone_records(Name) when is_binary(Name) ->
    Labels = dns:dname_to_lower_labels(Name),
    get_zone_records(Labels);
get_zone_records(Labels) when is_list(Labels) ->
    case find_zone_labels_in_cache(Labels) of
        zone_not_found ->
            [];
        ZoneLabels ->
            Pattern = {{{ZoneLabels, '_', '_'}, '$1'}, [], ['$1']},
            lists:append(ets:select(zone_records_typed, [Pattern]))
    end;
get_zone_records(#zone{labels = ZoneLabels}) ->
    Pattern = {{{ZoneLabels, '_', '_'}, '$1'}, [], ['$1']},
    lists:append(ets:select(zone_records_typed, [Pattern])).

-doc #{group => ~"API: Lookups"}.
-doc "Return the record set for the given dname.".
-spec get_records_by_name(dns:dname() | [dns:label()]) -> [dns:rr()].
get_records_by_name(Name) when is_binary(Name) ->
    Labels = dns:dname_to_lower_labels(Name),
    get_records_by_name(Labels);
get_records_by_name(Labels) when is_list(Labels) ->
    case find_zone_labels_in_cache(Labels) of
        zone_not_found ->
            [];
        ZoneLabels ->
            RecordLabels = reduce_record_labels(ZoneLabels, Labels),
            Pattern = {{{ZoneLabels, RecordLabels, '_'}, '$1'}, [], ['$1']},
            lists:append(ets:select(zone_records_typed, [Pattern]))
    end.

-doc #{group => ~"API: Lookups"}.
-doc "Return the record set for the given dname in the given zone.".
-spec get_records_by_name(erldns:zone(), dns:dname() | [dns:label()]) -> [dns:rr()].
get_records_by_name(Zone, Name) when is_binary(Name) ->
    Labels = dns:dname_to_lower_labels(Name),
    get_records_by_name(Zone, Labels);
get_records_by_name(#zone{labels = ZL}, Labels) when is_list(ZL), is_list(Labels) ->
    RecordLabels = reduce_record_labels(ZL, Labels),
    Pattern = {{{ZL, RecordLabels, '_'}, '$1'}, [], ['$1']},
    lists:append(ets:select(zone_records_typed, [Pattern])).

-doc #{group => ~"API: Lookups"}.
-doc "Return the record set for the given dname in the given zone, including wildcard matches.".
-spec get_records_by_name_wildcard(erldns:zone(), dns:dname() | [dns:label()]) -> [dns:rr()].
get_records_by_name_wildcard(Zone, Name) when is_binary(Name) ->
    Labels = dns:dname_to_lower_labels(Name),
    get_records_by_name_wildcard(Zone, Labels);
get_records_by_name_wildcard(#zone{labels = ZL}, Labels) when is_list(ZL), is_list(Labels) ->
    RecordLabels = reduce_record_labels(ZL, Labels),
    record_name_in_zone_with_wildcard(ZL, RecordLabels).

-doc #{group => ~"API: Lookups"}.
-doc "Return the record set for the given dname in the given zone, including descendants.".
-spec get_records_by_name_ent(erldns:zone(), dns:dname() | [dns:label()]) -> [dns:rr()].
get_records_by_name_ent(Zone, Name) when is_binary(Name) ->
    Labels = dns:dname_to_lower_labels(Name),
    get_records_by_name_ent(Zone, Labels);
get_records_by_name_ent(#zone{labels = ZL}, Labels) when is_list(ZL), is_list(Labels) ->
    RecordLabels = reduce_record_labels(ZL, Labels),
    record_name_in_zone_with_descendants(ZL, RecordLabels).

-doc #{group => ~"API: Lookups"}.
-doc "Get all records for the given type and given name.".
-spec get_records_by_name_and_type(dns:dname() | [dns:label()], dns:type()) -> [dns:rr()].
get_records_by_name_and_type(Name, Type) when is_binary(Name) ->
    Labels = dns:dname_to_lower_labels(Name),
    get_records_by_name_and_type(Labels, Type);
get_records_by_name_and_type(Labels, Type) when is_list(Labels) ->
    case find_zone_labels_in_cache(Labels) of
        zone_not_found ->
            [];
        ZoneLabels ->
            RecordLabels = reduce_record_labels(ZoneLabels, Labels),
            Pattern = {{{ZoneLabels, RecordLabels, Type}, '$1'}, [], ['$1']},
            lists:append(ets:select(zone_records_typed, [Pattern]))
    end.

-doc #{group => ~"API: Lookups"}.
-doc "Get all records for the given name and type in the given zone.".
-spec get_records_by_name_and_type(erldns:zone(), dns:dname() | [dns:label()], dns:type()) ->
    [dns:rr()].
get_records_by_name_and_type(Zone, Name, Type) when is_binary(Name) ->
    Labels = dns:dname_to_lower_labels(Name),
    get_records_by_name_and_type(Zone, Labels, Type);
get_records_by_name_and_type(#zone{labels = ZL}, Labels, Type) when is_list(ZL), is_list(Labels) ->
    RecordLabels = reduce_record_labels(ZL, Labels),
    Pattern = {{{ZL, RecordLabels, Type}, '$1'}, [], ['$1']},
    lists:append(ets:select(zone_records_typed, [Pattern])).

-doc #{group => ~"API: Lookups"}.
-doc "Find an authoritative zone for a given qname.".
-spec get_authoritative_zone([dns:label()]) -> erldns:zone() | zone_not_found | not_authoritative.
get_authoritative_zone(Labels) when is_list(Labels) ->
    find_authoritative_zone_in_cache(Labels).

-doc #{group => ~"API: Lookups"}.
-doc """
Get the list of NS and glue records for the given name.

This function will always return a list, even if it is empty.
""".
-spec get_delegations(dns:dname()) -> [dns:rr()].
get_delegations(Name) when is_binary(Name) ->
    NormalizedName = dns:dname_to_lower(Name),
    Labels = dns:dname_to_labels(NormalizedName),
    case find_zone_labels_in_cache(Labels) of
        zone_not_found ->
            [];
        ZoneLabels ->
            RecordLabels = reduce_record_labels(ZoneLabels, Labels),
            Pattern = {{{ZoneLabels, RecordLabels, ?DNS_TYPE_NS}, '$1'}, [], ['$1']},
            Records = lists:append(ets:select(zone_records_typed, [Pattern])),
            lists:filter(erldns_records:match_delegation(NormalizedName), Records)
    end.

-doc #{group => ~"API: lookups"}.
-doc "Return current sync counter".
-spec get_rrset_sync_counter(dns:dname(), dns:dname(), dns:type()) -> integer().
get_rrset_sync_counter(ZoneName, RRFqdn, Type) ->
    NormalizedZoneName = dns:dname_to_lower(ZoneName),
    NormalizedRRFqdn = dns:dname_to_lower(RRFqdn),
    Key = {NormalizedZoneName, NormalizedRRFqdn, Type},
    % return default value of 0
    ets:lookup_element(sync_counters, Key, 2, 0).

-doc #{group => ~"API: Boolean Operations"}.
-doc "Check if the name is in any available zone.".
-spec is_in_any_zone(dns:dname() | [dns:label()]) -> boolean().
is_in_any_zone(Name) when is_binary(Name) ->
    Labels = dns:dname_to_lower_labels(Name),
    is_in_any_zone(Labels);
is_in_any_zone(Labels) when is_list(Labels) ->
    case find_zone_labels_in_cache(Labels) of
        zone_not_found ->
            false;
        ZoneLabels ->
            RecordLabels = reduce_record_labels(ZoneLabels, Labels),
            is_name_in_zone(ZoneLabels, RecordLabels)
    end.

-doc #{group => ~"API: Boolean Operations"}.
-doc """
Check if the record name, or any wildcard, is in the zone.

Will also return true if a wildcard is present at the node.
""".
-spec is_record_name_in_zone(erldns:zone(), dns:dname() | [dns:label()]) -> boolean().
is_record_name_in_zone(Zone, Name) when is_binary(Name) ->
    Labels = dns:dname_to_lower_labels(Name),
    is_record_name_in_zone(Zone, Labels);
is_record_name_in_zone(#zone{labels = ZL}, Labels) when is_list(ZL), is_list(Labels) ->
    case lists:suffix(ZL, Labels) of
        false ->
            false;
        true ->
            RecordLabels = reduce_record_labels(ZL, Labels),
            is_record_name_in_zone_helper(ZL, RecordLabels)
    end.

-doc #{group => ~"API: Boolean Operations"}.
-doc """
Check if the record name, or any wildcard, or descendant, is in the zone.

Will also return true if a wildcard is present at the node,
or if any descendant has existing records (and the queried name is an ENT).
""".
-spec is_record_name_in_zone_strict(erldns:zone(), dns:dname() | [dns:label()]) -> boolean().
is_record_name_in_zone_strict(Zone, Name) when is_binary(Name) ->
    Labels = dns:dname_to_lower_labels(Name),
    is_record_name_in_zone_strict(Zone, Labels);
is_record_name_in_zone_strict(#zone{labels = ZL}, Labels) when is_list(ZL), is_list(Labels) ->
    case lists:suffix(ZL, Labels) of
        false ->
            false;
        true ->
            RecordLabels = reduce_record_labels(ZL, Labels),
            is_record_name_in_zone_helper(ZL, RecordLabels) orelse
                is_record_name_in_zone_with_descendants(ZL, RecordLabels)
    end.

-doc #{group => ~"API: Utilities"}.
-doc "Return a list of tuples with each tuple as a name and the version SHA for the zone.".
-spec zone_names_and_versions() -> [{dns:dname(), erldns_zones:version()}].
zone_names_and_versions() ->
    ets:foldl(
        fun(Zone, NamesAndShas) ->
            [{Zone#zone.name, Zone#zone.version} | NamesAndShas]
        end,
        [],
        zones
    ).

%% Update the RRSet sync counter for the given RR set name and type in the given zone.
-spec write_rrset_sync_counter(dns:dname(), dns:dname(), dns:type(), integer()) -> ok.
write_rrset_sync_counter(ZoneName, RRFqdn, Type, Counter) ->
    true = ets:insert(sync_counters, {{ZoneName, RRFqdn, Type}, Counter}),
    ok.

% Write API
%% All write operations write records with normalized names, hence reads won't need to
%% renormalize again and again

-doc #{group => ~"API: Zone inserts"}.
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
    Sha :: erldns_zones:version(),
    Records :: [dns:rr()],
    Keys :: [erldns:keyset()].
put_zone(#zone{name = Name} = Zone) ->
    NormalizedName = dns:dname_to_lower(Name),
    ZoneLabels = dns:dname_to_labels(NormalizedName),
    SignedZone = sign_zone(Zone#zone{name = NormalizedName, labels = ZoneLabels}),
    NamedRecords = build_named_index(SignedZone#zone.records),
    ZoneRecords = prepare_zone_records(ZoneLabels, NamedRecords),
    fix_tables(true),
    delete_zone_records(ZoneLabels),
    true = insert_zone(SignedZone#zone{records = []}),
    put_zone_records(ZoneRecords),
    fix_tables(false);
put_zone({Name, Sha, Records}) ->
    put_zone({Name, Sha, Records, []});
put_zone({Name, Sha, Records, Keys}) ->
    Zone = erldns_zone_codec:build_zone(Name, Sha, Records, Keys),
    put_zone(Zone).

-doc #{group => ~"API: Zone inserts"}.
-doc "Put zone RRSet".
-spec put_zone_rrset(RRSet, RRFqdn, Type, Counter) -> ok | zone_not_found when
    RRSet ::
        erldns:zone()
        | {dns:dname(), erldns_zones:version(), [dns:rr()]}
        | {dns:dname(), erldns_zones:version(), [dns:rr()], [term()]},
    RRFqdn :: dns:dname(),
    Type :: dns:type(),
    Counter :: integer().
put_zone_rrset(
    #zone{name = ZoneName, version = Digest, records = Records, keysets = KeySets},
    RRFqdn,
    Type,
    Counter
) ->
    put_zone_rrset({ZoneName, Digest, Records, KeySets}, RRFqdn, Type, Counter);
put_zone_rrset({ZoneName, Digest, Records}, RRFqdn, Type, Counter) ->
    put_zone_rrset({ZoneName, Digest, Records, []}, RRFqdn, Type, Counter);
put_zone_rrset({ZoneName, Digest, Records, _Keys}, RRFqdn, Type, Counter) ->
    NormalizedZoneName = dns:dname_to_lower(ZoneName),
    ZQLabels = dns:dname_to_labels(NormalizedZoneName),
    case find_zone_in_cache(ZQLabels) of
        #zone{labels = ZoneLabels} = Zone ->
            ?LOG_DEBUG(
                #{
                    what => putting_rrset,
                    rrset => RRFqdn,
                    type => Type,
                    zone => NormalizedZoneName,
                    records => Records
                },
                ?LOG_METADATA
            ),
            KeySets = Zone#zone.keysets,
            NormalizedRRFqdn = dns:dname_to_lower(RRFqdn),
            Labels = dns:dname_to_labels(NormalizedRRFqdn),
            SignedRRSet = sign_rrset(Zone#zone{records = Records, keysets = KeySets}),
            {RRSigRecsCovering, RRSigRecsNotCovering} = filter_rrsig_records_with_type_covered(
                Labels, Type
            ),
            % RRSet records + RRSIG records for the type + the rest of RRSIG records for FQDN
            CurrentRRSetRecords = get_records_by_name_and_type(Zone, Labels, Type),
            ZoneRecordsCount = Zone#zone.record_count,
            % put zone_records_typed records first then create the records in zone_records
            TypedRecords = Records ++ SignedRRSet ++ RRSigRecsNotCovering,
            put_zone_records_typed_entry(ZoneLabels, Labels, TypedRecords),
            UpdatedZoneRecordsCount =
                ZoneRecordsCount +
                    (length(Records) - length(CurrentRRSetRecords)) +
                    (length(SignedRRSet) - length(RRSigRecsCovering)),
            update_zone_records_and_digest(ZoneLabels, UpdatedZoneRecordsCount, Digest),
            write_rrset_sync_counter(NormalizedZoneName, NormalizedRRFqdn, Type, Counter),
            ?LOG_DEBUG(
                #{what => rrset_update_completed, rrset => NormalizedRRFqdn, type => Type},
                ?LOG_METADATA
            );
        % if zone is not in cache, return not found
        zone_not_found ->
            zone_not_found
    end.

-doc #{group => ~"API: Zone inserts"}.
-doc "Remove a zone from the cache without waiting for a response.".
-spec delete_zone(dns:dname() | [dns:label()]) -> term().
delete_zone(Name) when is_binary(Name) ->
    Labels = dns:dname_to_lower_labels(Name),
    delete_zone(Labels);
delete_zone(ZoneLabels) when is_list(ZoneLabels) ->
    ets:delete(zones, ZoneLabels),
    delete_zone_records(ZoneLabels).

-doc #{group => ~"API: Zone inserts"}.
-doc "Remove zone RRSet".
-spec delete_zone_rrset(dns:dname(), erldns_zones:version(), dns:dname(), integer(), integer()) ->
    ok | zone_not_found.
delete_zone_rrset(ZoneName, Digest, RRFqdn, Type, Counter) ->
    NormalizedZoneName = dns:dname_to_lower(ZoneName),
    ZQLabels = dns:dname_to_labels(NormalizedZoneName),
    case find_zone_in_cache(ZQLabels) of
        #zone{labels = ZoneLabels} = Zone ->
            CurrentCounter = get_rrset_sync_counter(ZoneName, RRFqdn, Type),
            case Counter of
                N when N =:= 0; CurrentCounter < N ->
                    ?LOG_DEBUG(
                        #{what => removing_rrset, rrset => RRFqdn, type => Type},
                        ?LOG_METADATA
                    ),
                    ZoneRecordsCount = Zone#zone.record_count,
                    NormalizedRRFqdn = dns:dname_to_lower(RRFqdn),
                    Labels = dns:dname_to_labels(NormalizedRRFqdn),
                    CurrentRRSetRecords = get_records_by_name_and_type(Zone, Labels, Type),
                    RecordLabels = reduce_record_labels(ZoneLabels, Labels),
                    Pattern = {{{ZoneLabels, RecordLabels, Type}, '_'}, [], [true]},
                    ets:select_delete(zone_records_typed, [Pattern]),
                    % remove the RRSIG for the given record type
                    {RRSigsCovering, RRSigsNotCovering} =
                        lists:partition(
                            erldns_records:match_type_covered(Type),
                            get_records_by_name_and_type(Zone, Labels, ?DNS_TYPE_RRSIG)
                        ),
                    do_put_zone_records_typed_entry(
                        ZoneLabels, Labels, ?DNS_TYPE_RRSIG, RRSigsNotCovering
                    ),
                    % only write counter if called explicitly with Counter value i.e.
                    % different than 0. this will not write the counter if called by
                    % put_zone_rrset/3 as it will prevent subsequent delete ops
                    case Counter of
                        N when N > 0 ->
                            % DELETE RRSet command has been sent
                            % we need to update the zone digest as the zone content changes
                            UpdatedZoneRecordsCount =
                                ZoneRecordsCount -
                                    length(CurrentRRSetRecords) -
                                    length(RRSigsCovering),
                            update_zone_records_and_digest(
                                ZoneLabels, UpdatedZoneRecordsCount, Digest
                            ),
                            write_rrset_sync_counter(NormalizedZoneName, RRFqdn, Type, Counter);
                        _ ->
                            ok
                    end;
                N when CurrentCounter > N ->
                    ?LOG_DEBUG(
                        #{
                            what => not_processing_delete_rrset,
                            reason => counter_lower_than_system,
                            rrset => RRFqdn,
                            counter => Counter
                        },
                        ?LOG_METADATA
                    )
            end;
        zone_not_found ->
            zone_not_found
    end.

-doc #{group => ~"API: Zone inserts"}.
-doc "Given a zone name, list of records, and a digest, update the zone metadata in cache.".
-spec update_zone_records_and_digest([dns:label()], non_neg_integer(), erldns_zones:version()) ->
    ok | zone_not_found.
update_zone_records_and_digest(ZLabels, RecordsCount, Digest) ->
    case find_zone_in_cache(ZLabels) of
        #zone{} = Zone ->
            UpdatedZone = Zone#zone{version = Digest, record_count = RecordsCount},
            true = insert_zone(UpdatedZone),
            ok;
        zone_not_found ->
            zone_not_found
    end.

% Internal API
-spec insert_zone(erldns:zone()) -> true.
insert_zone(#zone{} = Zone) ->
    ets:insert(zones, Zone).

%% Expects normalized names
-spec delete_zone_records([dns:label()]) -> term().
delete_zone_records(ZoneLabels) ->
    Pattern = {{{ZoneLabels, '_', '_'}, '_'}, [], [true]},
    ets:select_delete(zone_records_typed, [Pattern]).

%% expects name to be already normalized
-spec prepare_zone_records([dns:label()], #{dns:dname() => [dns:rr()]}) ->
    [{[dns:label()], [dns:label()], dns:type(), [dns:rr()]}].
prepare_zone_records(ZoneLabels, RecordsByName) ->
    lists:flatmap(
        fun({Fqdn, Records}) ->
            RecordLabels = dns:dname_to_lower_labels(Fqdn),
            TypedRecords = build_typed_index(Records),
            ListTypedRecords = maps:to_list(TypedRecords),
            prepare_zone_records_typed_entry(ZoneLabels, RecordLabels, ListTypedRecords)
        end,
        maps:to_list(RecordsByName)
    ).

%% expects name to be already normalized
-spec prepare_zone_records_typed_entry([dns:label()], [dns:label()], [{dns:type(), [dns:rr()]}]) ->
    [{[dns:label()], [dns:label()], dns:type(), [dns:rr()]}].
prepare_zone_records_typed_entry(ZoneLabels, RecordLabels, ListTypedRecords) ->
    lists:map(
        fun({Type, Records}) ->
            {ZoneLabels, RecordLabels, Type, Records}
        end,
        ListTypedRecords
    ).

%% expects name to be already normalized
-spec put_zone_records([{[dns:label()], [dns:label()], dns:type(), [dns:rr()]}]) -> ok.
put_zone_records(RecordsByName) ->
    lists:foreach(
        fun({ZoneLabels, RecordLabels, Type, Records}) ->
            do_put_zone_records_typed_entry(ZoneLabels, RecordLabels, Type, Records)
        end,
        RecordsByName
    ).

%% expects name to be already normalized
-spec put_zone_records_typed_entry([dns:label()], [dns:label()], [dns:rr()]) -> ok.
put_zone_records_typed_entry(ZoneLabels, RecordLabels, Records) ->
    TypedRecords = build_typed_index(Records),
    maps:foreach(
        fun(Type, Record) ->
            do_put_zone_records_typed_entry(ZoneLabels, RecordLabels, Type, Record)
        end,
        TypedRecords
    ).

-spec do_put_zone_records_typed_entry([dns:label()], [dns:label()], dns:type(), [dns:rr()]) -> true.
do_put_zone_records_typed_entry(ZoneLabels, RecordLabels, Type, Record) ->
    Labels = reduce_record_labels(ZoneLabels, RecordLabels),
    ets:insert(zone_records_typed, {{ZoneLabels, Labels, Type}, Record}).

%% record paths shall not cross the zone boundary,
%% hence we can cut the zone labels from the record labels
reduce_record_labels(ZoneLabels, RecordLabels) when is_list(ZoneLabels), is_list(RecordLabels) ->
    match_labels(lists:reverse(ZoneLabels), lists:reverse(RecordLabels)).

match_labels([], Rest) ->
    Rest;
match_labels([Label | ZoneLabels], [Label | RecordLabels]) ->
    match_labels(ZoneLabels, RecordLabels).

%% expects name to be already normalized
is_name_in_zone(ZoneLabels, RecordLabels) ->
    Pattern = {{{ZoneLabels, RecordLabels, '_'}, '$1'}, [], ['$1']},
    case lists:append(ets:select(zone_records_typed, [Pattern])) of
        [] ->
            case RecordLabels of
                [] ->
                    false;
                [_ | Rest] ->
                    is_name_in_zone(ZoneLabels, Rest)
            end;
        _ ->
            true
    end.

find_authoritative_zone_in_cache([]) ->
    zone_not_found;
find_authoritative_zone_in_cache([_ | Tail] = Labels) ->
    case ets:lookup(zones, Labels) of
        [#zone{authority = [_ | _]} = Zone] ->
            Zone;
        [#zone{authority = []}] ->
            not_authoritative;
        _ ->
            find_authoritative_zone_in_cache(Tail)
    end.

%% expects name to be already normalized
%% A positive return of this fuction implies that the zone exists and is a parent of the given name
-spec find_zone_labels_in_cache([dns:label()]) -> zone_not_found | dynamic().
find_zone_labels_in_cache([]) ->
    zone_not_found;
find_zone_labels_in_cache([_ | Tail] = Labels) ->
    case ets:lookup_element(zones, Labels, #zone.labels, zone_not_found) of
        zone_not_found ->
            find_zone_labels_in_cache(Tail);
        Elem when is_list(Elem) ->
            Elem
    end.

-spec find_zone_in_cache([dns:label()]) -> zone_not_found | erldns:zone().
find_zone_in_cache([]) ->
    zone_not_found;
find_zone_in_cache([_ | Tail] = Labels) ->
    case ets:lookup(zones, Labels) of
        [] ->
            find_zone_in_cache(Tail);
        [#zone{} = Zone] ->
            Zone
    end.

-spec build_named_index([dns:rr()]) -> #{dns:dname() => [dns:rr()]}.
build_named_index(Records) ->
    maps:groups_from_list(fun(R) -> dns:dname_to_lower(R#dns_rr.name) end, Records).

-spec build_typed_index([dns:rr()]) -> #{dns:type() => [dns:rr()]}.
build_typed_index(Records) ->
    maps:groups_from_list(fun(R) -> R#dns_rr.type end, Records).

-spec sign_zone(erldns:zone()) -> erldns:zone().
sign_zone(#zone{keysets = []} = Zone) ->
    Zone;
sign_zone(Zone) ->
    #{
        key_rrsig_rrs := KeyRRSigRecords,
        zone_rrsig_rrs := ZoneRRSigRecords
    } = erldns_dnssec:get_signed_records(Zone),
    Records =
        Zone#zone.records ++
            KeyRRSigRecords ++
            rewrite_soa_rrsig_ttl(Zone#zone.records, ZoneRRSigRecords),
    Zone#zone{
        record_count = length(Records),
        records = Records
    }.

% Sign RRSet
-spec sign_rrset(erldns:zone()) -> [dns:rr()].
sign_rrset(#zone{labels = ZoneLabels} = Zone) ->
    ZoneRecords = get_records_by_name_and_type(Zone, ZoneLabels, ?DNS_TYPE_SOA),
    ZoneRRSigRecords = erldns_dnssec:get_signed_zone_records(Zone),
    rewrite_soa_rrsig_ttl(ZoneRecords, ZoneRRSigRecords).

%% Filter RRSig records for FQDN, removing type covered..
-spec filter_rrsig_records_with_type_covered([dns:label()], dns:type()) ->
    {[dns:rr()], [dns:rr()]} | {[], []}.
filter_rrsig_records_with_type_covered(Labels, TypeCovered) ->
    % guards below do not allow fun calls to prevent side effects
    case find_zone_in_cache(Labels) of
        #zone{} = Zone ->
            % {RRSigsCovering, RRSigsNotCovering} =
            lists:partition(
                erldns_records:match_type_covered(TypeCovered),
                get_records_by_name_and_type(Zone, Labels, ?DNS_TYPE_RRSIG)
            );
        zone_not_found ->
            {[], []}
    end.

% Rewrite the RRSIG TTL so it follows the same rewrite rules as the SOA TTL.
rewrite_soa_rrsig_ttl(ZoneRecords, RRSigRecords) ->
    SoaRR = lists:keyfind(?DNS_TYPE_SOA, #dns_rr.type, ZoneRecords),
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

%% Checks if there is a wildcard record matching all the way to the last label.
record_name_in_zone_with_wildcard(_, []) ->
    [];
record_name_in_zone_with_wildcard(ZoneLabels, QLabels) ->
    Parent = lists:droplast(QLabels),
    WildcardPath = Parent ++ [~"*"],
    Pattern = {{{ZoneLabels, WildcardPath, '_'}, '$1'}, [], ['$1']},
    case lists:append(ets:select(zone_records_typed, [Pattern])) of
        [] ->
            record_name_in_zone_with_wildcard(ZoneLabels, Parent);
        RRs ->
            RRs
    end.

record_name_in_zone_with_descendants(ZoneLabels, QLabels) ->
    % eqwalizer:ignore this needs to be an improper list for tree traversal
    HasDescendantsPath = QLabels ++ '_',
    Pattern = {{{ZoneLabels, HasDescendantsPath, '_'}, '$1'}, [], ['$1']},
    lists:append(ets:select(zone_records_typed, [Pattern])).

is_record_name_in_zone_helper(ZoneLabels, RecordLabels) ->
    Pattern = {{{ZoneLabels, RecordLabels, '_'}, '_'}, [], [true]},
    case ets:select_count(zone_records_typed, [Pattern]) of
        0 ->
            is_record_name_in_zone_with_wildcard(ZoneLabels, RecordLabels);
        _ ->
            true
    end.

%% Checks if there is a wildcard record matching all the way to the last label.
is_record_name_in_zone_with_wildcard(_, []) ->
    false;
is_record_name_in_zone_with_wildcard(ZoneLabels, QLabels) ->
    Parent = lists:droplast(QLabels),
    WildcardPath = Parent ++ [~"*"],
    Pattern = {{{ZoneLabels, WildcardPath, '_'}, '_'}, [], [true]},
    case ets:select_count(zone_records_typed, [Pattern]) of
        0 ->
            is_record_name_in_zone_with_wildcard(ZoneLabels, Parent);
        _ ->
            true
    end.

is_record_name_in_zone_with_descendants(ZoneLabels, QLabels) ->
    % eqwalizer:ignore this needs to be an improper list for tree traversal
    HasDescendantsPath = QLabels ++ '_',
    Pattern = {{{ZoneLabels, HasDescendantsPath, '_'}, '_'}, [], [true]},
    0 =/= ets:select_count(zone_records_typed, [Pattern]).

fix_tables(Fix) ->
    ets:safe_fixtable(zone_records_typed, Fix),
    ets:safe_fixtable(zones, Fix),
    ok.

-doc #{group => ~"API: Utilities"}.
-doc "Testing helper, replicates cache tables".
-spec create(zones | zone_records_typed | sync_counters) -> ok.
create(zones) ->
    create_ets_table(zones, set, #zone.labels);
create(zone_records_typed) ->
    create_ets_table(zone_records_typed, ordered_set);
create(sync_counters) ->
    create_ets_table(sync_counters, set).

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
    ?LOG_INFO(#{what => unexpected_call, from => From, call => Call}, ?LOG_METADATA),
    {reply, not_implemented, State}.

-doc false.
-spec handle_cast(dynamic(), nostate) -> {noreply, nostate}.
handle_cast(Cast, State) ->
    ?LOG_INFO(#{what => unexpected_cast, cast => Cast}, ?LOG_METADATA),
    {noreply, State}.

-spec create_ets_table(atom(), ets:table_type()) -> ok.
create_ets_table(TableName, Type) ->
    create_ets_table(TableName, Type, 1).

-spec create_ets_table(atom(), ets:table_type(), non_neg_integer()) -> ok.
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
