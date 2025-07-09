-module(erldns_zone_cache).
-moduledoc """
A cache holding all of the zone data.

This module expects all input to use normalised (that is, lowercase) names, therefore it is the
responsibility of the client to call this API with normalised names.
This is to avoid normalising already normalised names, which can result into computational waste.
As the client might need to call multiple points of this API, the client can ensure to normalise
once and use multiple times.
""".

%% This module's gen_server holds three tables:
%%
%% 1. `erldns_zones_table`:
%% Holds the zones themselves as `#zone{}` records,
%% where the key is the zone's label set (`#zone.labels`).
%%
%% 2. `erldns_zone_records_typed`:
%% Holds all RR records, where keys look like,
%% `{<zone labels>, <reverse record path up to the zone>, dns:type()}`
%% For example, if the zone is `example.com` and the record is `a2.a1.example.com` type A:
%% `{[<<"example">>, <<"com">>], [<<"a1">>, <<"a2">>], ?DNS_TYPE_A]}`
%%
%% This serves two purposes: smaller memory footprint, and when traversing the tree for a path in a
%% zone, traversal will forcefully stop when it arrives at the parent zone, ensuring no resources
%% are waste looking for a record above the zone boundary.
%%
%% 3. `erldns_sync_counters`:
%% Holds a counter of updates for each RR.

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
    get_records_by_name_and_type/2,
    get_records_by_name_and_type/3,
    get_records_by_name_ent/2,
    get_records_by_name_wildcard/2,
    get_records_by_name_wildcard_strict/2,
    get_authoritative_zone/1,
    get_delegations/1,
    get_rrset_sync_counter/3,
    is_in_any_zone/1,
    is_name_in_zone/2,
    is_record_name_in_zone/2,
    is_record_name_in_zone_strict/2
]).

%% Other
-export([
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
-spec lookup_zone(dns:dname() | dns:labels()) -> erldns:zone() | zone_not_found.
lookup_zone(Name) when is_binary(Name) ->
    Labels = dns:dname_to_labels(Name),
    lookup_zone(Labels);
lookup_zone(Labels) when is_list(Labels) ->
    case ets:lookup(erldns_zones_table, Labels) of
        [] ->
            zone_not_found;
        [#zone{} = Zone] ->
            Zone
    end.

-doc #{group => ~"API: Lookups"}.
-doc "Get all records for the given zone.".
-spec get_zone_records(erldns:zone() | dns:dname() | dns:labels()) -> [dns:rr()].
get_zone_records(Name) when is_binary(Name) ->
    Labels = dns:dname_to_labels(Name),
    get_zone_records(Labels);
get_zone_records(Labels) when is_list(Labels) ->
    case find_zone_labels_in_cache(Labels) of
        zone_not_found ->
            [];
        ZoneLabels ->
            pattern_zone(ZoneLabels)
    end;
get_zone_records(#zone{labels = ZoneLabels}) ->
    pattern_zone(ZoneLabels).

-doc #{group => ~"API: Lookups"}.
-doc "Return the record set for the given dname.".
-spec get_records_by_name(dns:dname() | dns:labels()) -> [dns:rr()].
get_records_by_name(Name) when is_binary(Name) ->
    Labels = dns:dname_to_labels(Name),
    get_records_by_name(Labels);
get_records_by_name(Labels) when is_list(Labels) ->
    case find_zone_labels_in_cache(Labels) of
        zone_not_found ->
            [];
        ZoneLabels ->
            RecordLabels = reduce_record_labels(ZoneLabels, Labels),
            pattern_zone_dname(ZoneLabels, RecordLabels)
    end.

-doc #{group => ~"API: Lookups"}.
-doc "Return the record set for the given dname in the given zone.".
-spec get_records_by_name(erldns:zone(), dns:dname() | dns:labels()) -> [dns:rr()].
get_records_by_name(Zone, Name) when is_binary(Name) ->
    Labels = dns:dname_to_labels(Name),
    get_records_by_name(Zone, Labels);
get_records_by_name(#zone{labels = ZL}, Labels) when is_list(ZL), is_list(Labels) ->
    RecordLabels = reduce_record_labels(ZL, Labels),
    pattern_zone_dname(ZL, RecordLabels).

-doc #{group => ~"API: Lookups"}.
-doc "Get all records for the given type and given name.".
-spec get_records_by_name_and_type(dns:dname() | dns:labels(), dns:type()) -> [dns:rr()].
get_records_by_name_and_type(Name, Type) when is_binary(Name) ->
    Labels = dns:dname_to_labels(Name),
    get_records_by_name_and_type(Labels, Type);
get_records_by_name_and_type(Labels, Type) when is_list(Labels) ->
    case find_zone_labels_in_cache(Labels) of
        zone_not_found ->
            [];
        ZoneLabels ->
            RecordLabels = reduce_record_labels(ZoneLabels, Labels),
            pattern_zone_dname_type(ZoneLabels, RecordLabels, Type)
    end.

-doc #{group => ~"API: Lookups"}.
-doc "Get all records for the given name and type in the given zone.".
-spec get_records_by_name_and_type(erldns:zone(), dns:dname() | dns:labels(), dns:type()) ->
    [dns:rr()].
get_records_by_name_and_type(Zone, Name, Type) when is_binary(Name) ->
    Labels = dns:dname_to_labels(Name),
    get_records_by_name_and_type(Zone, Labels, Type);
get_records_by_name_and_type(#zone{labels = ZL}, Labels, Type) when is_list(ZL), is_list(Labels) ->
    RecordLabels = reduce_record_labels(ZL, Labels),
    pattern_zone_dname_type(ZL, RecordLabels, Type).

-doc #{group => ~"API: Lookups"}.
-doc "Return the full record set for the tree below the given dname".
-spec get_records_by_name_ent(erldns:zone(), dns:dname() | dns:labels()) -> [dns:rr()].
get_records_by_name_ent(Zone, Name) when is_binary(Name) ->
    Labels = dns:dname_to_labels(Name),
    get_records_by_name_ent(Zone, Labels);
get_records_by_name_ent(#zone{labels = ZL}, Labels) when is_list(ZL), is_list(Labels) ->
    RecordLabels = reduce_record_labels(ZL, Labels),
    record_name_in_zone_with_descendants(ZL, RecordLabels).

-doc #{group => ~"API: Lookups"}.
-doc """
Return the record set for the given dname in the given zone, including parent wildcard matches.
""".
-spec get_records_by_name_wildcard(erldns:zone(), dns:dname() | dns:labels()) -> [dns:rr()].
get_records_by_name_wildcard(Zone, Name) when is_binary(Name) ->
    Labels = dns:dname_to_labels(Name),
    get_records_by_name_wildcard(Zone, Labels);
get_records_by_name_wildcard(#zone{labels = ZL}, Labels) when is_list(ZL), is_list(Labels) ->
    RecordLabels = reduce_record_labels(ZL, Labels),
    record_name_in_zone_with_wildcard(ZL, RecordLabels).

-doc #{group => ~"API: Lookups"}.
-doc """
Return the record set for the given dname in the given zone,
including parent exact and wildcard matches.
""".
-spec get_records_by_name_wildcard_strict(erldns:zone(), dns:dname() | dns:labels()) -> [dns:rr()].
get_records_by_name_wildcard_strict(Zone, Name) when is_binary(Name) ->
    Labels = dns:dname_to_labels(Name),
    get_records_by_name_wildcard_strict(Zone, Labels);
get_records_by_name_wildcard_strict(#zone{labels = ZL}, Labels) when is_list(ZL), is_list(Labels) ->
    RecordLabels = reduce_record_labels(ZL, Labels),
    record_name_in_zone_with_wildcard_strict(ZL, RecordLabels).

-doc #{group => ~"API: Lookups"}.
-doc "Find an authoritative zone for a given qname.".
-spec get_authoritative_zone(dns:dname() | dns:labels()) ->
    erldns:zone() | zone_not_found | not_authoritative.
get_authoritative_zone(Name) when is_binary(Name) ->
    Labels = dns:dname_to_labels(Name),
    find_authoritative_zone_in_cache(Labels);
get_authoritative_zone(Labels) when is_list(Labels) ->
    find_authoritative_zone_in_cache(Labels).

-doc #{group => ~"API: Lookups"}.
-doc """
Get the list of NS and glue records for the given name.

This function will always return a list, even if it is empty.
""".
-spec get_delegations(dns:dname() | dns:labels()) -> [dns:rr()].
get_delegations(Name) when is_binary(Name) ->
    Labels = dns:dname_to_labels(Name),
    get_delegations(Name, Labels);
get_delegations(Labels) when is_list(Labels) ->
    Name = dns:labels_to_dname(Labels),
    get_delegations(Name, Labels).

-doc #{group => ~"API: Lookups"}.
-doc "Return current sync counter".
-spec get_rrset_sync_counter(dns:dname(), dns:dname(), dns:type()) -> integer().
get_rrset_sync_counter(NormalizedZoneName, RRFqdn, Type) ->
    NormalizedRRFqdn = dns:dname_to_lower(RRFqdn),
    Key = {NormalizedZoneName, NormalizedRRFqdn, Type},
    % return default value of 0
    ets:lookup_element(erldns_sync_counters, Key, 2, 0).

-doc #{group => ~"API: Boolean Operations"}.
-doc "Check if the name is in any available zone.".
-spec is_in_any_zone(dns:dname() | dns:labels()) -> boolean().
is_in_any_zone(Name) when is_binary(Name) ->
    Labels = dns:dname_to_labels(Name),
    is_in_any_zone(Labels);
is_in_any_zone(Labels) when is_list(Labels) ->
    case find_zone_labels_in_cache(Labels) of
        zone_not_found ->
            false;
        ZoneLabels ->
            RecordLabels = reduce_record_labels(ZoneLabels, Labels),
            is_name_in_any_zone_helper(ZoneLabels, RecordLabels)
    end.

-doc #{group => ~"API: Boolean Operations"}.
-doc """
Check if the exact record name is in the zone, without recursing nor traversing the zone tree.
""".
-spec is_name_in_zone(erldns:zone(), dns:dname() | dns:labels()) -> boolean().
is_name_in_zone(Zone, Name) when is_binary(Name) ->
    Labels = dns:dname_to_labels(Name),
    is_name_in_zone(Zone, Labels);
is_name_in_zone(#zone{labels = ZL}, Labels) when is_list(ZL), is_list(Labels) ->
    case reduce_record_labels(ZL, Labels) of
        false ->
            false;
        RecordLabels ->
            0 =/= pattern_zone_dname_count(ZL, RecordLabels)
    end.

-doc #{group => ~"API: Boolean Operations"}.
-doc "Check if the record name, or any wildcard or parent wildcard, is in the zone.".
-spec is_record_name_in_zone(erldns:zone(), dns:dname() | dns:labels()) -> boolean().
is_record_name_in_zone(Zone, Name) when is_binary(Name) ->
    Labels = dns:dname_to_labels(Name),
    is_record_name_in_zone(Zone, Labels);
is_record_name_in_zone(#zone{labels = ZL}, Labels) when is_list(ZL), is_list(Labels) ->
    case reduce_record_labels(ZL, Labels) of
        false ->
            false;
        RecordLabels ->
            is_record_name_in_zone_helper(ZL, RecordLabels)
    end.

-doc #{group => ~"API: Boolean Operations"}.
-doc """
Check if the record name, or any wildcard, or parent wildcard, or descendant, is in the zone.

Will also return true if a wildcard is present at the node,
or if any descendant has existing records (and the queried name is an ENT).
""".
-spec is_record_name_in_zone_strict(erldns:zone(), dns:dname() | dns:labels()) -> boolean().
is_record_name_in_zone_strict(Zone, Name) when is_binary(Name) ->
    Labels = dns:dname_to_labels(Name),
    is_record_name_in_zone_strict(Zone, Labels);
is_record_name_in_zone_strict(#zone{labels = ZL}, Labels) when is_list(ZL), is_list(Labels) ->
    case reduce_record_labels(ZL, Labels) of
        false ->
            false;
        RecordLabels ->
            is_record_name_in_zone_helper(ZL, RecordLabels) orelse
                is_record_name_in_zone_with_descendants(ZL, RecordLabels)
    end.

-doc #{group => ~"API: Utilities"}.
-doc "Return a list of tuples with each tuple as a name and the version SHA for the zone.".
-spec zone_names_and_versions() -> [{dns:dname(), erldns_zones:version()}].
zone_names_and_versions() ->
    ets:foldl(
        fun(#zone{name = Name, version = Version}, NamesAndShas) ->
            [{Name, Version} | NamesAndShas]
        end,
        [],
        erldns_zones_table
    ).

%% Update the RRSet sync counter for the given RR set name and type in the given zone.
-spec write_rrset_sync_counter(dns:dname(), dns:dname(), dns:type(), integer()) -> ok.
write_rrset_sync_counter(ZoneName, RRFqdn, Type, Counter) ->
    true = ets:insert(erldns_sync_counters, {{ZoneName, RRFqdn, Type}, Counter}),
    ok.

% Write API
%% All write operations write records with normalized names, hence reads won't need to
%% renormalize again and again

-doc #{group => ~"API: Mutations"}.
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
    true = insert_zone(SignedZone#zone{records = []}),
    NumDeleted = delete_zone_records(ZoneLabels),
    maybe_notify_of_zone_replacement(NumDeleted, NormalizedName),
    put_zone_records(ZoneRecords),
    ok;
put_zone({Name, Sha, Records}) ->
    put_zone({Name, Sha, Records, []});
put_zone({Name, Sha, Records, Keys}) ->
    Zone = erldns_zone_codec:build_zone(Name, Sha, Records, Keys),
    put_zone(Zone).

-doc #{group => ~"API: Mutations"}.
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
            RecordLabels = dns:dname_to_labels(NormalizedRRFqdn),
            SignedRRSet = sign_rrset(Zone#zone{records = Records, keysets = KeySets}),
            {RRSigRecsCovering, RRSigRecsNotCovering} = filter_rrsig_records_with_type_covered(
                RecordLabels, Type
            ),
            % RRSet records + RRSIG records for the type + the rest of RRSIG records for FQDN
            CurrentRRSetRecords = get_records_by_name_and_type(Zone, RecordLabels, Type),
            ZoneRecordsCount = Zone#zone.record_count,
            % put erldns_zone_records_typed records first then create the records in zone_records
            TypedRecords = Records ++ SignedRRSet ++ RRSigRecsNotCovering,
            Labels = reduce_record_labels(ZoneLabels, RecordLabels),
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
            ),
            ok;
        % if zone is not in cache, return not found
        zone_not_found ->
            zone_not_found
    end.

-doc #{group => ~"API: Mutations"}.
-doc "Remove a zone from the cache without waiting for a response.".
-spec delete_zone(dns:dname() | dns:labels()) -> term().
delete_zone(Name) when is_binary(Name) ->
    Labels = dns:dname_to_labels(Name),
    delete_zone(Labels);
delete_zone(ZoneLabels) when is_list(ZoneLabels) ->
    ets:delete(erldns_zones_table, ZoneLabels),
    delete_zone_records(ZoneLabels).

-doc #{group => ~"API: Mutations"}.
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
                N when N =:= 0; CurrentCounter =< N ->
                    ?LOG_DEBUG(
                        #{what => removing_rrset, rrset => RRFqdn, type => Type},
                        ?LOG_METADATA
                    ),
                    ZoneRecordsCount = Zone#zone.record_count,
                    NormalizedRRFqdn = dns:dname_to_lower(RRFqdn),
                    RecordLabels = dns:dname_to_labels(NormalizedRRFqdn),
                    CurrentRRSetRecords = get_records_by_name_and_type(Zone, RecordLabels, Type),
                    ReducedLabels = reduce_record_labels(ZoneLabels, RecordLabels),
                    pattern_zone_dname_type_delete(ZoneLabels, ReducedLabels, Type),
                    % remove the RRSIG for the given record type
                    {RRSigsCovering, RRSigsNotCovering} =
                        lists:partition(
                            erldns_records:match_type_covered(Type),
                            get_records_by_name_and_type(Zone, RecordLabels, ?DNS_TYPE_RRSIG)
                        ),
                    do_put_zone_records_typed_entry(
                        ZoneLabels, ReducedLabels, ?DNS_TYPE_RRSIG, RRSigsNotCovering
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

-doc #{group => ~"API: Mutations"}.
-doc "Given a zone name, list of records, and a digest, update the zone metadata in cache.".
-spec update_zone_records_and_digest(dns:labels(), non_neg_integer(), erldns_zones:version()) ->
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
    ets:insert(erldns_zones_table, Zone).

%% Expects normalized names
-spec delete_zone_records(dns:labels()) -> non_neg_integer().
delete_zone_records(ZoneLabels) ->
    pattern_zone_delete(ZoneLabels).

%% expects name to be already normalized
-spec prepare_zone_records(dns:labels(), #{dns:dname() => [dns:rr()]}) ->
    [{dns:labels(), dns:labels(), dns:type(), [dns:rr()]}].
prepare_zone_records(ZoneLabels, RecordsByName) ->
    lists:flatmap(
        fun({Fqdn, Records}) ->
            RecordLabels = dns:dname_to_labels(Fqdn),
            TypedRecords = build_typed_index(Records),
            ListTypedRecords = maps:to_list(TypedRecords),
            prepare_zone_records_typed_entry(ZoneLabels, RecordLabels, ListTypedRecords)
        end,
        maps:to_list(RecordsByName)
    ).

%% expects name to be already normalized
-spec prepare_zone_records_typed_entry(dns:labels(), dns:labels(), [{dns:type(), [dns:rr()]}]) ->
    [{dns:labels(), dns:labels(), dns:type(), [dns:rr()]}].
prepare_zone_records_typed_entry(ZoneLabels, RecordLabels, ListTypedRecords) ->
    lists:map(
        fun({Type, Records}) ->
            ReducedLabels = reduce_record_labels(ZoneLabels, RecordLabels),
            {ZoneLabels, ReducedLabels, Type, Records}
        end,
        ListTypedRecords
    ).

%% Expects record labels to be already reduced
-spec put_zone_records([{dns:labels(), dns:labels(), dns:type(), [dns:rr()]}]) -> ok.
put_zone_records(RecordsByName) ->
    lists:foreach(
        fun({ZoneLabels, ReducedLabels, Type, Records}) ->
            do_put_zone_records_typed_entry(ZoneLabels, ReducedLabels, Type, Records)
        end,
        RecordsByName
    ).

%% Expects record labels to be already reduced
-spec put_zone_records_typed_entry(dns:labels(), dns:labels(), [dns:rr()]) -> ok.
put_zone_records_typed_entry(ZoneLabels, ReducedLabels, Records) ->
    TypedRecords = build_typed_index(Records),
    maps:foreach(
        fun(Type, Record) ->
            do_put_zone_records_typed_entry(ZoneLabels, ReducedLabels, Type, Record)
        end,
        TypedRecords
    ).

%% Expects record labels to be already reduced
-spec do_put_zone_records_typed_entry(dns:labels(), dns:labels(), dns:type(), [dns:rr()]) -> true.
do_put_zone_records_typed_entry(ZoneLabels, ReducedLabels, Type, Record) ->
    ets:insert(erldns_zone_records_typed, {{ZoneLabels, ReducedLabels, Type}, Record}).

%% record paths shall not cross the zone boundary,
%% hence we can cut the zone labels from the record labels
reduce_record_labels(ZoneLabels, RecordLabels) when is_list(ZoneLabels), is_list(RecordLabels) ->
    match_labels(lists:reverse(ZoneLabels), lists:reverse(RecordLabels)).

match_labels([], Rest) ->
    Rest;
match_labels([Label | ZoneLabels], [Label | RecordLabels]) ->
    match_labels(ZoneLabels, RecordLabels);
match_labels([_ | _], [_ | _]) ->
    false.

%% expects name to be already normalized
is_name_in_any_zone_helper(ZoneLabels, []) ->
    0 =/= pattern_zone_dname_count(ZoneLabels, []);
is_name_in_any_zone_helper(ZoneLabels, [_ | ParentLabels] = RecordLabels) ->
    0 =/= pattern_zone_dname_count(ZoneLabels, RecordLabels) orelse
        is_name_in_any_zone_helper(ZoneLabels, ParentLabels).

find_authoritative_zone_in_cache([]) ->
    zone_not_found;
find_authoritative_zone_in_cache([_ | Tail] = Labels) ->
    case ets:lookup(erldns_zones_table, Labels) of
        [#zone{authority = [_ | _]} = Zone] ->
            Zone;
        [#zone{authority = []}] ->
            not_authoritative;
        _ ->
            find_authoritative_zone_in_cache(Tail)
    end.

get_delegations(Name, Labels) ->
    case find_zone_labels_in_cache(Labels) of
        zone_not_found ->
            [];
        ZoneLabels ->
            RecordLabels = reduce_record_labels(ZoneLabels, Labels),
            Records = pattern_zone_dname_type(ZoneLabels, RecordLabels, ?DNS_TYPE_NS),
            lists:filter(erldns_records:match_delegation(Name), Records)
    end.

%% expects name to be already normalized
%% A positive return of this fuction implies that the zone exists and is a parent of the given name
-spec find_zone_labels_in_cache(dns:labels()) -> zone_not_found | dynamic().
find_zone_labels_in_cache([]) ->
    zone_not_found;
find_zone_labels_in_cache([_ | Tail] = Labels) ->
    case ets:lookup_element(erldns_zones_table, Labels, #zone.labels, zone_not_found) of
        zone_not_found ->
            find_zone_labels_in_cache(Tail);
        Elem when is_list(Elem) ->
            Elem
    end.

-spec find_zone_in_cache(dns:labels()) -> zone_not_found | erldns:zone().
find_zone_in_cache([]) ->
    zone_not_found;
find_zone_in_cache([_ | Tail] = Labels) ->
    case ets:lookup(erldns_zones_table, Labels) of
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
-spec filter_rrsig_records_with_type_covered(dns:labels(), dns:type()) ->
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
    SoaRR = #dns_rr{} = lists:keyfind(?DNS_TYPE_SOA, #dns_rr.type, ZoneRecords),
    lists:map(
        fun
            (#dns_rr{type = ?DNS_TYPE_RRSIG, data = #dns_rrdata_rrsig{} = Data} = RR) ->
                case Data#dns_rrdata_rrsig.type_covered of
                    ?DNS_TYPE_SOA -> erldns_records:minimum_soa_ttl(RR, SoaRR#dns_rr.data);
                    _ -> RR
                end;
            (#dns_rr{} = RR) ->
                RR
        end,
        RRSigRecords
    ).

record_name_in_zone_with_descendants(ZoneLabels, QLabels) ->
    % eqwalizer:ignore this needs to be an improper list for tree traversal
    HasDescendantsPath = QLabels ++ '_',
    pattern_zone_dname(ZoneLabels, HasDescendantsPath).

%% Checks if there is a wildcard record matching all the way to the last label.
record_name_in_zone_with_wildcard(_, []) ->
    [];
record_name_in_zone_with_wildcard(ZoneLabels, QLabels) ->
    Parent = lists:droplast(QLabels),
    WildcardPath = Parent ++ [~"*"],
    case pattern_zone_dname(ZoneLabels, WildcardPath) of
        [] ->
            record_name_in_zone_with_wildcard(ZoneLabels, Parent);
        RRsWild ->
            RRsWild
    end.

% Find the best match records for the given QName in the given zone.
% This will attempt to walk through the domain hierarchy in the QName
% looking for both exact and wildcard matches.
record_name_in_zone_with_wildcard_strict(_, []) ->
    [];
record_name_in_zone_with_wildcard_strict(ZoneLabels, [_ | _] = RecordLabels) ->
    Parent = lists:droplast(RecordLabels),
    WildcardLabels = Parent ++ [~"*"],
    case pattern_zone_dname(ZoneLabels, WildcardLabels) of
        [] ->
            case pattern_zone_dname(ZoneLabels, Parent) of
                [] ->
                    record_name_in_zone_with_wildcard_strict(ZoneLabels, Parent);
                RRsStrict ->
                    RRsStrict
            end;
        RRsWild ->
            RRsWild
    end.

is_record_name_in_zone_helper(ZoneLabels, RecordLabels) ->
    is_record_name_in_zone_traverse_wildcard(ZoneLabels, RecordLabels, RecordLabels).

is_record_name_in_zone_with_wildcard(_, []) ->
    false;
is_record_name_in_zone_with_wildcard(ZoneLabels, QLabels) ->
    Parent = lists:droplast(QLabels),
    WildcardPath = Parent ++ [~"*"],
    is_record_name_in_zone_traverse_wildcard(ZoneLabels, WildcardPath, Parent).

is_record_name_in_zone_traverse_wildcard(ZoneLabels, Path, ParentPath) ->
    0 =/= pattern_zone_dname_count(ZoneLabels, Path) orelse
        is_record_name_in_zone_with_wildcard(ZoneLabels, ParentPath).

is_record_name_in_zone_with_descendants(ZoneLabels, QLabels) ->
    % eqwalizer:ignore this needs to be an improper list for tree traversal
    HasDescendantsPath = QLabels ++ '_',
    0 =/= pattern_zone_dname_count(ZoneLabels, HasDescendantsPath).

pattern_zone(ZoneLabels) ->
    Pattern = {{{ZoneLabels, '_', '_'}, '$1'}, [], ['$1']},
    lists:append(ets:select(erldns_zone_records_typed, [Pattern])).

pattern_zone_dname(ZoneLabels, Labels) ->
    Pattern = {{{ZoneLabels, Labels, '_'}, '$1'}, [], ['$1']},
    lists:append(ets:select(erldns_zone_records_typed, [Pattern])).

pattern_zone_dname_type(ZoneLabels, Labels, Type) ->
    Pattern = {{{ZoneLabels, Labels, Type}, '$1'}, [], ['$1']},
    lists:append(ets:select(erldns_zone_records_typed, [Pattern])).

pattern_zone_dname_count(ZoneLabels, Labels) ->
    Pattern = {{{ZoneLabels, Labels, '_'}, '$1'}, [], [true]},
    ets:select_count(erldns_zone_records_typed, [Pattern]).

pattern_zone_dname_type_delete(ZoneLabels, Labels, Type) ->
    Pattern = {{{ZoneLabels, Labels, Type}, '_'}, [], [true]},
    ets:select_delete(erldns_zone_records_typed, [Pattern]).

pattern_zone_delete(ZoneLabels) ->
    Pattern = {{{ZoneLabels, '_', '_'}, '_'}, [], [true]},
    ets:select_delete(erldns_zone_records_typed, [Pattern]).

maybe_notify_of_zone_replacement(0, _) ->
    ok;
maybe_notify_of_zone_replacement(NumDeleted, NormalizedName) ->
    ?LOG_WARNING(
        #{what => zone_replaced, zone => NormalizedName, records_deleted => NumDeleted},
        ?LOG_METADATA
    ).

-doc false.
-spec start_link() -> term().
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, noargs, [{hibernate_after, 0}]).

-doc false.
-spec init(noargs) -> {ok, nostate}.
init(noargs) ->
    create_ets_table(erldns_zones_table, set, #zone.labels),
    create_ets_table(erldns_zone_records_typed, ordered_set),
    create_ets_table(erldns_sync_counters, set),
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
    ok.
