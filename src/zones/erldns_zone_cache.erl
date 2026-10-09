-module(erldns_zone_cache).
-moduledoc """
A cache holding all of the zone data.

This module expects all input to use normalised (that is, lowercase) names, therefore it is the
responsibility of the client to call this API with normalised names.
This is to avoid normalising already normalised names, which can result into computational waste.
As the client might need to call multiple points of this API, the client can ensure to normalise
once and use multiple times.

## Replacing a zone

A zone's records are written under a generation that no lookup reaches until the zone's header,
which names that generation, is published. `put_zone/1` writes and publishes in one call;
`stage_zone/1` and `commit_zone/1` split the two, so that changes arriving while a large zone is
being written can be carried onto it with `stage_zone_rrset/4` and `stage_zone_rrset_deletion/3`
before it goes live. Either way a query sees the zone as it was or as it became, never part-way.

Lookups go through the generation of the `#zone{}` header they are given, so a query that holds
one keeps reading the same version of the zone throughout, and the header must come from this
cache: one built by the caller names no generation, and finds no records. The generation a commit
replaces stays readable for the `grace_period` set under `zones` (see `m:erldns_zones`), so that
queries already holding its header can finish, and is deleted after that.

A staged zone belongs to the process that staged it, as an ETS table does. If that process exits
before the zone is committed or discarded, the cache drops the zone's records, and committing it
afterwards returns `{error, not_staged}`. Another process may commit or discard it meanwhile.

## Telemetry events

### `[erldns, zone, put]`

Emitted at the end of `commit_zone/1`, and so of `put_zone/1`, once the zone is published.

- Measurements:
```erlang
count := 1
```
- Metadata:
```erlang
zone_name := dns:dname()
zone_labels := dns:labels()
```

### `[erldns, zone, delete]`

Emitted at the end of `delete_zone/1`, after the zone and its sync counters have been removed.
Its records follow once the `grace_period` has passed.

- Measurements:
```erlang
count := 1
```
- Metadata:
```erlang
zone_name := dns:dname()
zone_labels := dns:labels()
```
""".

%% This module's gen_server holds three tables:
%%
%% 1. `erldns_zones_table`:
%% Holds the zones themselves as `#zone{}` records,
%% where the key is the zone's label set (`#zone.labels`).
%%
%% 2. `erldns_zone_records_typed`:
%% Holds all RR records, where keys look like,
%% `{<generation>, <reverse record path up to the zone>, dns:type()}`
%% For example, if the zone `example.com` is at generation 42 and the record is
%% `a2.a1.example.com` type A:
%% `{42, [<<"a1">>, <<"a2">>], ?DNS_TYPE_A]}`
%%
%% A generation is unique to one staging of one zone, so it stands for the zone in the key. This
%% serves three purposes: smaller memory footprint; when traversing the tree for a path in a zone,
%% traversal will forcefully stop when it arrives at the parent zone, ensuring no resources are
%% wasted looking for a record above the zone boundary; and a whole zone can be written under a new
%% generation while lookups keep reading the old one, until the zone's header switches over.
%%
%% 3. `erldns_sync_counters`:
%% Holds a counter of updates for each RR, keyed by
%% `{<zone labels>, <reduced record labels>, dns:type()}`. Keyed by zone rather than generation,
%% because a counter outlives the generation it was written under.
%%
%% 4. `erldns_staged_zones`:
%% Holds `{<generation>, <zone labels>, <owner pid>}` for every generation staged and not yet
%% committed or discarded. Committing, discarding, and dropping it when its owner exits each start
%% by taking this entry, so exactly one of them decides what becomes of the generation.

-behaviour(gen_server).

-include_lib("dns_erlang/include/dns.hrl").
-include_lib("kernel/include/logger.hrl").
-include_lib("erldns/include/erldns.hrl").

-define(LOG_METADATA, #{domain => [erldns, zones]}).
-define(DEFAULT_GRACE_PERIOD, 30000).

-type generation() :: non_neg_integer().
%% The processes that have staged a zone, each monitored once.
-type owners() :: #{pid() => reference()}.

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
    get_records_by_name_resolved/2,
    get_records_by_name_and_type_resolved/3,
    get_authoritative_zone/1,
    get_authoritative_zone/2,
    get_zonecut/2,
    get_delegations/1,
    get_delegations/2,
    get_rrset_sync_counter/3,
    is_in_any_zone/1,
    is_name_in_zone/2,
    is_record_name_in_zone/2,
    is_record_name_in_zone_strict/2,
    zone_name_existence/2
]).

-doc """
Classification of a name in a zone.

It can be:
- exact (records at node)
- wildcard (matched by a parent wildcard)
- ent (empty non-terminal)
- or nxdomain (not in zone)
""".
-type existence_type() :: ent | nxdomain | exact | wildcard.

-doc """
One-shot resolution result.

It can be:
- `ent`
- `nxdomain`
- `{exact, [dns:rr()]}` — records at the query name (list may be empty for typed lookup)
- `{wildcard, [dns:rr()]}` — records from a parent wildcard (list may be empty for typed lookup)
""".
-type resolved_records() ::
    ent
    | nxdomain
    | {exact, [dns:rr()]}
    | {wildcard, [dns:rr()]}.

-export_type([existence_type/0, resolved_records/0]).

%% Other
-export([
    zone_names_and_versions/0,
    put_zone/1,
    stage_zone/1,
    commit_zone/1,
    discard_zone/1,
    stage_zone_rrset/4,
    stage_zone_rrset_deletion/3,
    delete_zone/1,
    update_zone_records_and_digest/3,
    put_zone_rrset/4,
    delete_zone_rrset/5
]).

-export([start_link/0, init/1, handle_call/3, handle_cast/2, handle_info/2]).

-doc #{group => ~"API: Lookups"}.
-doc """
Get a zone for the specific name.

This function will not attempt to resolve the dname in any way,
it will simply look up the name in the underlying data store.
""".
-spec lookup_zone(dns:dname() | dns:labels()) -> erldns:zone() | zone_not_found.
lookup_zone(Name) when is_binary(Name) ->
    Labels = dns_domain:split(Name),
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
    Labels = dns_domain:split(Name),
    get_zone_records(Labels);
get_zone_records(Labels) when is_list(Labels) ->
    case find_zone_generation(Labels) of
        zone_not_found ->
            [];
        {_ZoneLabels, Gen} ->
            pattern_zone(Gen)
    end;
get_zone_records(#zone{gen = Gen}) ->
    pattern_zone(Gen).

-doc #{group => ~"API: Lookups"}.
-doc "Return the record set for the given dname.".
-spec get_records_by_name(dns:dname() | dns:labels()) -> [dns:rr()].
get_records_by_name(Name) when is_binary(Name) ->
    Labels = dns_domain:split(Name),
    get_records_by_name(Labels);
get_records_by_name(Labels) when is_list(Labels) ->
    case find_zone_generation(Labels) of
        zone_not_found ->
            [];
        {ZoneLabels, Gen} ->
            RecordLabels = reduce_record_labels(ZoneLabels, Labels),
            pattern_zone_dname(Gen, RecordLabels)
    end.

-doc #{group => ~"API: Lookups"}.
-doc """
Return the record set for the given dname in the given zone.

Returns only exact records at that node; no wildcard expansion and no subtree.
""".
-spec get_records_by_name(erldns:zone(), dns:dname() | dns:labels()) -> [dns:rr()].
get_records_by_name(Zone, Name) when is_binary(Name) ->
    Labels = dns_domain:split(Name),
    get_records_by_name(Zone, Labels);
get_records_by_name(#zone{labels = ZL, reversed_labels = RZL, gen = Gen}, Labels) when
    is_list(ZL), is_list(RZL), is_list(Labels)
->
    RecordLabels = reduce_record_labels_pre_reversed(RZL, Labels),
    pattern_zone_dname(Gen, RecordLabels).

-doc #{group => ~"API: Lookups"}.
-doc "Get all records for the given type and given name.".
-spec get_records_by_name_and_type(dns:dname() | dns:labels(), dns:type()) -> [dns:rr()].
get_records_by_name_and_type(Name, Type) when is_binary(Name) ->
    Labels = dns_domain:split(Name),
    get_records_by_name_and_type(Labels, Type);
get_records_by_name_and_type(Labels, Type) when is_list(Labels) ->
    case find_zone_generation(Labels) of
        zone_not_found ->
            [];
        {ZoneLabels, Gen} ->
            RecordLabels = reduce_record_labels(ZoneLabels, Labels),
            pattern_zone_dname_type(Gen, RecordLabels, Type)
    end.

-doc #{group => ~"API: Lookups"}.
-doc "Get all records for the given name and type in the given zone.".
-spec get_records_by_name_and_type(erldns:zone(), dns:dname() | dns:labels(), dns:type()) ->
    [dns:rr()].
get_records_by_name_and_type(Zone, Name, Type) when is_binary(Name) ->
    Labels = dns_domain:split(Name),
    get_records_by_name_and_type(Zone, Labels, Type);
get_records_by_name_and_type(
    #zone{labels = ZL, reversed_labels = RZL, gen = Gen}, Labels, Type
) when
    is_list(ZL), is_list(RZL), is_list(Labels)
->
    RecordLabels = reduce_record_labels_pre_reversed(RZL, Labels),
    pattern_zone_dname_type(Gen, RecordLabels, Type).

-doc #{group => ~"API: Lookups"}.
-doc """
Return the entire subtree at the given dname: all records at that node and at any descendant.
""".
-spec get_records_by_name_ent(erldns:zone(), dns:dname() | dns:labels()) -> [dns:rr()].
get_records_by_name_ent(Zone, Name) when is_binary(Name) ->
    Labels = dns_domain:split(Name),
    get_records_by_name_ent(Zone, Labels);
get_records_by_name_ent(#zone{labels = ZL, reversed_labels = RZL, gen = Gen}, Labels) when
    is_list(ZL), is_list(RZL), is_list(Labels)
->
    RecordLabels = reduce_record_labels_pre_reversed(RZL, Labels),
    record_name_in_zone_with_descendants(Gen, RecordLabels).

-doc #{group => ~"API: Lookups"}.
-doc """
Return records for the given dname or at any parent that has a wildcard.

Walks from the name upward; at each level looks only for a wildcard (`*.parent`).
Stops at the first wildcard found and returns those records. Does not consider
exact records at ancestors, and does not block on ENT (empty non-terminals).
""".
-spec get_records_by_name_wildcard(erldns:zone(), dns:dname() | dns:labels()) -> [dns:rr()].
get_records_by_name_wildcard(Zone, Name) when is_binary(Name) ->
    Labels = dns_domain:split(Name),
    get_records_by_name_wildcard(Zone, Labels);
get_records_by_name_wildcard(#zone{labels = ZL, reversed_labels = RZL, gen = Gen}, Labels) when
    is_list(ZL), is_list(RZL), is_list(Labels)
->
    RecordLabels = reduce_record_labels_pre_reversed(RZL, Labels),
    record_name_in_zone_with_wildcard(Gen, RecordLabels).

-doc #{group => ~"API: Lookups"}.
-doc """
Return records for the given dname or at any parent that has a wildcard or exact records.

Walks from the name upward; at each level looks for a wildcard first, then for
exact records at that parent. Stops at the first level that has either and
returns those records. Does not block on ENT (empty non-terminals); only
prefers exact over wildcard when both exist at the same level.
""".
-spec get_records_by_name_wildcard_strict(erldns:zone(), dns:dname() | dns:labels()) -> [dns:rr()].
get_records_by_name_wildcard_strict(Zone, Name) when is_binary(Name) ->
    Labels = dns_domain:split(Name),
    get_records_by_name_wildcard_strict(Zone, Labels);
get_records_by_name_wildcard_strict(
    #zone{labels = ZL, reversed_labels = RZL, gen = Gen}, Labels
) when
    is_list(ZL), is_list(RZL), is_list(Labels)
->
    RecordLabels = reduce_record_labels_pre_reversed(RZL, Labels),
    record_name_in_zone_with_wildcard_strict(Gen, RecordLabels).

-doc #{group => ~"API: Lookups"}.
-doc """
Return matching records or a status when there are none.

One-shot resolution: returns either
- the atom `nxdomain` (name does not exist in the zone),
- the atom `ent` (empty non-terminal: no records at this node but it has descendants),
- `{exact, Records}` (records at the query name; list is non-empty for untyped lookup),
- `{wildcard, Records}` (records from a parent wildcard; list is non-empty for untyped lookup).
""".
-spec get_records_by_name_resolved(erldns:zone(), dns:dname() | dns:labels()) ->
    resolved_records().
get_records_by_name_resolved(Zone, Name) ->
    get_records_by_name_and_type_resolved_1(Zone, Name, '_').

-doc #{group => ~"API: Lookups"}.
-doc """
Return matching records of the given type, or a status when there are none.

Same as `get_records_by_name_resolved/2` but only returns records of the given `dns:type()`.
""".
-spec get_records_by_name_and_type_resolved(
    erldns:zone(), dns:dname() | dns:labels(), dns:type()
) ->
    resolved_records().
get_records_by_name_and_type_resolved(Zone, Name, Type) ->
    get_records_by_name_and_type_resolved_1(Zone, Name, Type).

get_records_by_name_and_type_resolved_1(Zone, Name, Type) when is_binary(Name) ->
    get_records_by_name_and_type_resolved_1(Zone, dns_domain:split(Name), Type);
get_records_by_name_and_type_resolved_1(
    #zone{labels = ZL, reversed_labels = RZL, gen = Gen}, Labels, Type
) when
    is_list(ZL), is_list(RZL), is_list(Labels)
->
    case reduce_record_labels_pre_reversed(RZL, Labels) of
        false ->
            nxdomain;
        RecordLabels ->
            get_records_resolved_1(Gen, RecordLabels, Type)
    end.

-doc #{group => ~"API: Lookups"}.
-doc "Find an authoritative zone for a given qname.".
-spec get_authoritative_zone(dns:dname() | dns:labels()) ->
    erldns:zone() | zone_not_found | not_authoritative.
get_authoritative_zone(Name) when is_binary(Name) ->
    Labels = dns_domain:split(Name),
    find_authoritative_zone_in_cache(Labels);
get_authoritative_zone(Labels) when is_list(Labels) ->
    find_authoritative_zone_in_cache(Labels).

-doc #{group => ~"API: Lookups"}.
-doc "Find an authoritative zone for a given qname and qtype.".
-spec get_authoritative_zone(dns:labels(), dns:type()) ->
    erldns:zone() | zone_not_found | not_authoritative.
get_authoritative_zone(Labels, ?DNS_TYPE_DS) ->
    find_authoritative_zone_in_cache_ds(Labels);
get_authoritative_zone(Labels, _) ->
    get_authoritative_zone(Labels).

-doc #{group => ~"API: Lookups"}.
-doc """
Find the zone cut a name sits at or below.

Returns the labels of the topmost name between the apex and the given name that holds an NS
RRset, with that RRset, or `none`. The apex is not a cut, and a cut under another cut is occluded
by it, hence the topmost.
""".
-spec get_zonecut(erldns:zone(), dns:dname() | dns:labels()) ->
    none | {dns:labels(), [dns:rr(), ...]}.
get_zonecut(Zone, Name) when is_binary(Name) ->
    get_zonecut(Zone, dns_domain:split(Name));
get_zonecut(#zone{labels = ZL, reversed_labels = RZL, gen = Gen}, Labels) when
    is_list(ZL), is_list(RZL), is_list(Labels)
->
    case reduce_record_labels_pre_reversed(RZL, Labels) of
        false -> none;
        RecordLabels -> find_zonecut(ZL, Gen, RecordLabels, [])
    end.

%% Reduced labels run from the apex outwards, so the first prefix holding an NS RRset is the
%% topmost cut.
find_zonecut(_, _, [], _) ->
    none;
find_zonecut(ZL, Gen, [Label | Rest], Prefix) ->
    RecordLabels = Prefix ++ [Label],
    case pattern_zone_dname_type(Gen, RecordLabels, ?DNS_TYPE_NS) of
        [] -> find_zonecut(ZL, Gen, Rest, RecordLabels);
        NSRecords -> {lists:reverse(RecordLabels, ZL), NSRecords}
    end.

-doc #{group => ~"API: Lookups"}.
-doc """
Get the list of NS and glue records for the given name.

This function will always return a list, even if it is empty.
""".
-spec get_delegations(dns:dname() | dns:labels()) -> [dns:rr()].
get_delegations(Name) when is_binary(Name) ->
    Labels = dns_domain:split(Name),
    do_get_delegations(Name, Labels);
get_delegations(Labels) when is_list(Labels) ->
    Name = dns_domain:join(Labels),
    do_get_delegations(Name, Labels).

-doc #{group => ~"API: Lookups"}.
-doc """
Get the list of NS and glue records for the given name.

Expects name and labels to refer to the same domain.

This function will always return a list, even if it is empty.
""".
-spec get_delegations(dns:dname(), dns:labels()) -> [dns:rr()].
get_delegations(Name, Labels) when is_binary(Name), is_list(Labels) ->
    do_get_delegations(Name, Labels).

-doc #{group => ~"API: Lookups"}.
-doc "Return current sync counter".
-spec get_rrset_sync_counter(dns:dname() | dns:labels(), dns:dname() | dns:labels(), dns:type()) ->
    integer().
get_rrset_sync_counter(ZoneName, RRFqdn, Type) when is_binary(ZoneName) ->
    NormalizedZoneNameLabels = dns_domain:split(dns_domain:to_lower(ZoneName)),
    get_rrset_sync_counter(NormalizedZoneNameLabels, RRFqdn, Type);
get_rrset_sync_counter(ZoneName, RRFqdn, Type) when is_binary(RRFqdn) ->
    NormalizedRRFqdnLabels = dns_domain:split(dns_domain:to_lower(RRFqdn)),
    get_rrset_sync_counter(ZoneName, NormalizedRRFqdnLabels, Type);
get_rrset_sync_counter(ZoneNameLabels, RRFqdnLabels, Type) when
    is_list(ZoneNameLabels), is_list(RRFqdnLabels)
->
    ReducedLabels = reduce_record_labels(ZoneNameLabels, RRFqdnLabels),
    Key = {ZoneNameLabels, ReducedLabels, Type},
    % return default value of 0
    ets:lookup_element(erldns_sync_counters, Key, 2, 0).

-doc #{group => ~"API: Boolean Operations"}.
-doc "Check if the name is in any available zone.".
-spec is_in_any_zone(dns:dname() | dns:labels()) -> boolean().
is_in_any_zone(Name) when is_binary(Name) ->
    Labels = dns_domain:split(Name),
    is_in_any_zone(Labels);
is_in_any_zone(Labels) when is_list(Labels) ->
    case find_zone_generation(Labels) of
        zone_not_found ->
            false;
        {ZoneLabels, Gen} ->
            RecordLabels = reduce_record_labels(ZoneLabels, Labels),
            is_name_in_any_zone_helper(Gen, RecordLabels)
    end.

-doc #{group => ~"API: Boolean Operations"}.
-doc """
Check if the exact record name is in the zone, without recursing nor traversing the zone tree.
""".
-spec is_name_in_zone(erldns:zone(), dns:dname() | dns:labels()) -> boolean().
is_name_in_zone(Zone, Name) when is_binary(Name) ->
    Labels = dns_domain:split(Name),
    is_name_in_zone(Zone, Labels);
is_name_in_zone(#zone{labels = ZL, reversed_labels = RZL, gen = Gen}, Labels) when
    is_list(ZL), is_list(RZL), is_list(Labels)
->
    case reduce_record_labels_pre_reversed(RZL, Labels) of
        false ->
            false;
        RecordLabels ->
            pattern_zone_dname_exists(Gen, RecordLabels)
    end.

-doc #{group => ~"API: Boolean Operations"}.
-doc "Check if the record name, or any wildcard or parent wildcard, is in the zone.".
-spec is_record_name_in_zone(erldns:zone(), dns:dname() | dns:labels()) -> boolean().
is_record_name_in_zone(Zone, Name) when is_binary(Name) ->
    Labels = dns_domain:split(Name),
    is_record_name_in_zone(Zone, Labels);
is_record_name_in_zone(Zone, Labels) when is_list(Labels) ->
    Existence = zone_name_existence(Zone, Labels),
    (exact =:= Existence) orelse (wildcard =:= Existence).

-doc #{group => ~"API: Boolean Operations"}.
-doc """
Check if the record name, or any wildcard, or parent wildcard, or descendant, is in the zone.

Will also return true if a wildcard is present at the node,
or if any descendant has existing records (and the queried name is an ENT).
""".
-spec is_record_name_in_zone_strict(erldns:zone(), dns:dname() | dns:labels()) -> boolean().
is_record_name_in_zone_strict(Zone, Name) when is_binary(Name) ->
    Labels = dns_domain:split(Name),
    is_record_name_in_zone_strict(Zone, Labels);
is_record_name_in_zone_strict(Zone, Labels) when is_list(Labels) ->
    Existence = zone_name_existence(Zone, Labels),
    (exact =:= Existence) orelse (wildcard =:= Existence) orelse (ent =:= Existence).

-doc #{group => ~"API: Boolean Operations"}.
-doc """
Single-pass classification of how a name exists in the zone.

This can return: exact match, wildcard match, empty non-terminal (ENT), or nxdomain (no match).
Note that according to RFC4592, wildcards match only non-existing names;
this means that an ENT blocks a wildcard.
""".
-spec zone_name_existence(erldns:zone(), dns:dname() | dns:labels()) -> existence_type().
zone_name_existence(Zone, Name) when is_binary(Name) ->
    zone_name_existence(Zone, dns_domain:split(Name));
zone_name_existence(#zone{labels = ZL, reversed_labels = RZL, gen = Gen}, Labels) when
    is_list(ZL), is_list(RZL), is_list(Labels)
->
    case reduce_record_labels_pre_reversed(RZL, Labels) of
        false ->
            nxdomain;
        RecordLabels ->
            zone_name_existence_1(Gen, RecordLabels)
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
%% The key uses reduced labels (relative to the zone) for consistency
%% with erldns_zone_records_typed.
-spec write_rrset_sync_counter(dns:labels(), dns:labels(), dns:type(), integer()) -> term().
write_rrset_sync_counter(ZoneNameLabels, RRFqdnLabels, Type, Counter) when
    is_list(ZoneNameLabels), is_list(RRFqdnLabels)
->
    ReducedLabels = reduce_record_labels(ZoneNameLabels, RRFqdnLabels),
    ets:insert(erldns_sync_counters, {{ZoneNameLabels, ReducedLabels, Type}, Counter}).

% Write API
%% All write operations write records with normalized names, hence reads won't need to
%% renormalize again and again

-doc #{group => ~"API: Mutations"}.
-doc """
Put a name and its records into the cache, along with a SHA which can be
used to determine if the zone requires updating.

This function will build the necessary Zone record before inserting.

The name of each record must be the fully qualified domain name (including the zone part).

A zone already in the cache is replaced atomically: it is `commit_zone(stage_zone(Zone))`.

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
put_zone(Zone) ->
    ok = commit_zone(stage_zone(Zone)).

-doc #{group => ~"API: Mutations"}.
-doc """
Write a zone's records into the cache without publishing them.

Takes the same input as `put_zone/1`, and returns the zone's header, which no lookup reaches until
`commit_zone/1` publishes it. Until then `stage_zone_rrset/4` and `stage_zone_rrset_deletion/3`
can change it further. A staged zone that will not be published is dropped with `discard_zone/1`,
or when the calling process exits.
""".
-spec stage_zone(Zone | {Name, Sha, Records} | {Name, Sha, Records, Keys}) -> erldns:zone() when
    Zone :: erldns:zone(),
    Name :: dns:dname(),
    Sha :: erldns_zones:version(),
    Records :: [dns:rr()],
    Keys :: [erldns:keyset()].
stage_zone(#zone{name = Name} = Zone) ->
    NormalizedName = dns_domain:to_lower(Name),
    ZoneLabels = dns_domain:split(NormalizedName),
    Gen = erlang:unique_integer([positive, monotonic]),
    true = ets:insert(erldns_staged_zones, {Gen, ZoneLabels, self()}),
    gen_server:cast(?MODULE, {watch, self()}),
    SignedZone = sign_zone(Zone#zone{
        name = NormalizedName,
        labels = ZoneLabels,
        reversed_labels = lists:reverse(ZoneLabels),
        gen = Gen
    }),
    NamedRecords = build_named_index(SignedZone#zone.records),
    put_zone_records(prepare_zone_records(ZoneLabels, Gen, NamedRecords)),
    SignedZone#zone{records = []};
stage_zone({Name, Sha, Records}) ->
    stage_zone({Name, Sha, Records, []});
stage_zone({Name, Sha, Records, Keys}) ->
    Zone = erldns_zone_codec:build_zone(Name, Sha, Records, Keys),
    stage_zone(Zone).

-doc #{group => ~"API: Mutations"}.
-doc """
Publish a zone staged with `stage_zone/1`, replacing the zone's previous version if any.

The records it replaces are deleted once the `grace_period` has passed. Returns
`{error, not_staged}` if the zone was discarded, or dropped because the process that staged it
exited; committing a zone already published again is a no-op.
""".
-spec commit_zone(erldns:zone()) -> ok | {error, not_staged}.
commit_zone(#zone{gen = Gen} = Zone) ->
    case ets:take(erldns_staged_zones, Gen) of
        [_] -> publish_staged(Zone);
        [] -> settled(Zone)
    end.

-doc #{group => ~"API: Mutations"}.
-doc "Drop the records of a zone staged with `stage_zone/1`, unless it has since been published.".
-spec discard_zone(erldns:zone()) -> ok.
discard_zone(#zone{gen = Gen} = Zone) ->
    _ = ets:take(erldns_staged_zones, Gen),
    _ = settled(Zone),
    ok.

-doc #{group => ~"API: Mutations"}.
-doc """
Write an RRSet into a zone staged with `stage_zone/1`, signing it if the zone is signed.

Returns the zone's header with its record count and authority brought up to date. Unlike
`put_zone_rrset/4`, it checks and writes no sync counter, and sets no version.
""".
-spec stage_zone_rrset(erldns:zone(), dns:dname(), dns:type(), [dns:rr()]) -> erldns:zone().
stage_zone_rrset(
    #zone{labels = ZoneLabels, gen = Gen, record_count = Count} = Zone, RRFqdn, Type, Records
) ->
    ?LOG_DEBUG(
        #{
            what => putting_rrset,
            rrset => RRFqdn,
            type => Type,
            zone => Zone#zone.name,
            records => Records
        },
        ?LOG_METADATA
    ),
    RecordLabels = dns_domain:split(dns_domain:to_lower(RRFqdn)),
    SignedRRSet = sign_rrset(Zone#zone{records = Records}),
    {RRSigRecsCovering, RRSigRecsNotCovering} = partition_rrsigs(Zone, RecordLabels, Type),
    CurrentRRSetRecords = get_records_by_name_and_type(Zone, RecordLabels, Type),
    % RRSet records + RRSIG records for the type + the rest of RRSIG records for FQDN
    TypedRecords = Records ++ SignedRRSet ++ RRSigRecsNotCovering,
    ReducedLabels = reduce_record_labels(ZoneLabels, RecordLabels),
    put_zone_records_typed_entry(Gen, ReducedLabels, TypedRecords),
    UpdatedCount =
        Count +
            (length(Records) - length(CurrentRRSetRecords)) +
            (length(SignedRRSet) - length(RRSigRecsCovering)),
    with_authority(Zone#zone{record_count = UpdatedCount}).

-doc #{group => ~"API: Mutations"}.
-doc """
Remove an RRSet, and the RRSIG records covering it, from a zone staged with `stage_zone/1`.

Returns the zone's header with its record count and authority brought up to date. Unlike
`delete_zone_rrset/5`, it checks and writes no sync counter, and sets no version.
""".
-spec stage_zone_rrset_deletion(erldns:zone(), dns:dname(), dns:type()) -> erldns:zone().
stage_zone_rrset_deletion(
    #zone{labels = ZoneLabels, gen = Gen, record_count = Count} = Zone, RRFqdn, Type
) ->
    ?LOG_DEBUG(#{what => removing_rrset, rrset => RRFqdn, type => Type}, ?LOG_METADATA),
    RecordLabels = dns_domain:split(dns_domain:to_lower(RRFqdn)),
    CurrentRRSetRecords = get_records_by_name_and_type(Zone, RecordLabels, Type),
    {RRSigsCovering, RRSigsNotCovering} = partition_rrsigs(Zone, RecordLabels, Type),
    ReducedLabels = reduce_record_labels(ZoneLabels, RecordLabels),
    pattern_zone_dname_type_delete(Gen, ReducedLabels, Type),
    % Don't put an empty RRSIG in the cache
    case RRSigsNotCovering of
        [] ->
            pattern_zone_dname_type_delete(Gen, ReducedLabels, ?DNS_TYPE_RRSIG);
        _ ->
            put_zone_records([{{Gen, ReducedLabels, ?DNS_TYPE_RRSIG}, RRSigsNotCovering}])
    end,
    UpdatedCount = Count - length(CurrentRRSetRecords) - length(RRSigsCovering),
    with_authority(Zone#zone{record_count = UpdatedCount}).

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
    #zone{name = ZoneName, version = Digest, records = Records},
    RRFqdn,
    Type,
    Counter
) ->
    put_zone_rrset({ZoneName, Digest, Records}, RRFqdn, Type, Counter);
put_zone_rrset({ZoneName, Digest, Records, _}, RRFqdn, Type, Counter) ->
    put_zone_rrset({ZoneName, Digest, Records}, RRFqdn, Type, Counter);
put_zone_rrset({ZoneName, Digest, Records} = RRSet, RRFqdn, Type, Counter) ->
    ZQLabels = dns_domain:split(dns_domain:to_lower(ZoneName)),
    case find_zone_in_cache(ZQLabels) of
        #zone{} = Zone ->
            Updated = stage_zone_rrset(Zone, RRFqdn, Type, Records),
            case replace_zone(Zone, Updated#zone{version = Digest}) of
                true ->
                    RecordLabels = dns_domain:split(dns_domain:to_lower(RRFqdn)),
                    write_rrset_sync_counter(ZQLabels, RecordLabels, Type, Counter),
                    ?LOG_DEBUG(
                        #{what => rrset_update_completed, rrset => RRFqdn, type => Type},
                        ?LOG_METADATA
                    ),
                    ok;
                false ->
                    put_zone_rrset(RRSet, RRFqdn, Type, Counter)
            end;
        % if zone is not in cache, return not found
        zone_not_found ->
            zone_not_found
    end.

-doc #{group => ~"API: Mutations"}.
-doc """
Remove a zone from the cache.

The zone stops resolving at once; its records are deleted once the `grace_period` has passed.
""".
-spec delete_zone(dns:dname() | dns:labels()) -> term().
delete_zone(Name) when is_binary(Name) ->
    Labels = dns_domain:split(Name),
    delete_zone(Labels);
delete_zone(ZoneLabels) when is_list(ZoneLabels) ->
    unpublish(ZoneLabels),
    delete_zone_sync_counters(ZoneLabels),
    ZoneName = dns_domain:join(ZoneLabels, fqdn),
    Metadata = #{zone_name => ZoneName, zone_labels => ZoneLabels},
    telemetry:execute([erldns, zone, delete], #{count => 1}, Metadata).

-doc #{group => ~"API: Mutations"}.
-doc "Remove zone RRSet".
-spec delete_zone_rrset(dns:dname(), erldns_zones:version(), dns:dname(), integer(), integer()) ->
    ok | zone_not_found.
delete_zone_rrset(ZoneName, Digest, RRFqdn, Type, Counter) ->
    ZQLabels = dns_domain:split(dns_domain:to_lower(ZoneName)),
    RRFqdnLabels = dns_domain:split(dns_domain:to_lower(RRFqdn)),
    case find_zone_in_cache(ZQLabels) of
        #zone{} = Zone ->
            CurrentCounter = get_rrset_sync_counter(ZQLabels, RRFqdnLabels, Type),
            case Counter of
                0 ->
                    % only write counter if called explicitly with Counter value i.e.
                    % different than 0. this will not write the counter if called by
                    % put_zone_rrset/3 as it will prevent subsequent delete ops
                    _ = stage_zone_rrset_deletion(Zone, RRFqdn, Type),
                    ok;
                N when CurrentCounter =< N ->
                    % DELETE RRSet command has been sent
                    % we need to update the zone digest as the zone content changes
                    Updated = stage_zone_rrset_deletion(Zone, RRFqdn, Type),
                    case replace_zone(Zone, Updated#zone{version = Digest}) of
                        true ->
                            write_rrset_sync_counter(ZQLabels, RRFqdnLabels, Type, Counter),
                            ok;
                        false ->
                            delete_zone_rrset(ZoneName, Digest, RRFqdn, Type, Counter)
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
                    ),
                    ok
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
            UpdatedZone = with_authority(Zone#zone{version = Digest, record_count = RecordsCount}),
            case replace_zone(Zone, UpdatedZone) of
                true -> ok;
                false -> update_zone_records_and_digest(ZLabels, RecordsCount, Digest)
            end;
        zone_not_found ->
            zone_not_found
    end.

% Internal API

-spec publish_staged(erldns:zone()) -> ok.
publish_staged(#zone{name = Name, labels = ZoneLabels, gen = Gen} = Zone) ->
    case publish(Zone) of
        #zone{gen = Replaced, record_count = Count} when Replaced =/= Gen ->
            ?LOG_WARNING(
                #{what => zone_replaced, zone => Name, records_replaced => Count},
                ?LOG_METADATA
            ),
            retire_generation(Replaced);
        _ ->
            ok
    end,
    delete_zone_sync_counters(ZoneLabels),
    Metadata = #{zone_name => Name, zone_labels => ZoneLabels},
    telemetry:execute([erldns, zone, put], #{count => 1}, Metadata),
    ok.

%% A generation whose staging entry is gone was published, or dropped. Records written into a
%% dropped one since are dropped too: nothing can publish it any more.
-spec settled(erldns:zone()) -> ok | {error, not_staged}.
settled(#zone{labels = ZoneLabels, gen = Gen}) ->
    case ets:lookup_element(erldns_zones_table, ZoneLabels, #zone.gen, none) of
        Gen ->
            ok;
        _ ->
            drop_generation(Gen),
            {error, not_staged}
    end.

%% Publishes a zone's header, returning the one it replaced, if any.
-spec publish(erldns:zone()) -> erldns:zone() | none.
publish(#zone{labels = ZoneLabels} = Zone) ->
    case ets:lookup(erldns_zones_table, ZoneLabels) of
        [] ->
            case ets:insert_new(erldns_zones_table, Zone) of
                true -> none;
                false -> publish(Zone)
            end;
        [#zone{} = Current] ->
            case replace_zone(Current, Zone) of
                true -> Current;
                false -> publish(Zone)
            end
    end.

-spec unpublish(dns:labels()) -> ok.
unpublish(ZoneLabels) ->
    case ets:lookup_element(erldns_zones_table, ZoneLabels, #zone.gen, none) of
        none ->
            ok;
        Gen ->
            case
                ets:select_delete(erldns_zones_table, [{match_zone(ZoneLabels, Gen), [], [true]}])
            of
                1 -> retire_generation(Gen);
                0 -> unpublish(ZoneLabels)
            end
    end.

%% Swaps a zone's header only while it still names the generation it was read with, so that a
%% write racing a commit or a delete cannot point the zone back at records being retired.
-spec replace_zone(erldns:zone(), erldns:zone()) -> boolean().
replace_zone(#zone{labels = ZoneLabels, gen = Gen}, Updated) ->
    MatchSpec = [{match_zone(ZoneLabels, Gen), [], [{const, Updated}]}],
    1 =:= ets:select_replace(erldns_zones_table, MatchSpec).

-spec match_zone(dns:labels(), generation()) -> tuple().
match_zone(ZoneLabels, Gen) ->
    erlang:make_tuple(record_info(size, zone), '_', [
        {1, zone}, {#zone.labels, ZoneLabels}, {#zone.gen, Gen}
    ]).

-spec with_authority(erldns:zone()) -> erldns:zone().
with_authority(#zone{labels = ZoneLabels} = Zone) ->
    Zone#zone{authority = get_records_by_name_and_type(Zone, ZoneLabels, ?DNS_TYPE_SOA)}.

-spec retire_generation(generation()) -> ok.
retire_generation(Gen) ->
    erlang:send_after(grace_period(), ?MODULE, {drop_generation, Gen}),
    ok.

-spec grace_period() -> non_neg_integer().
grace_period() ->
    maps:get(grace_period, application:get_env(erldns, zones, #{}), ?DEFAULT_GRACE_PERIOD).

%% expects name to be already normalized
-spec prepare_zone_records(dns:labels(), generation(), #{dns:dname() => [dns:rr()]}) ->
    [{{generation(), dns:labels(), dns:type()}, [dns:rr()]}].
prepare_zone_records(ZoneLabels, Gen, RecordsByName) ->
    lists:flatmap(
        fun({Fqdn, Records}) ->
            ReducedLabels = reduce_record_labels(ZoneLabels, dns_domain:split(Fqdn)),
            [
                {{Gen, ReducedLabels, Type}, RRSet}
             || Type := RRSet <- build_typed_index(Records)
            ]
        end,
        maps:to_list(RecordsByName)
    ).

%% One insert per entry rather than one for the list: an insert is isolated, and holding the table
%% for a whole large zone would stall every lookup on the node.
-spec put_zone_records([{{generation(), dns:labels(), dns:type()}, [dns:rr()]}]) -> ok.
put_zone_records(Entries) ->
    lists:foreach(fun(Entry) -> ets:insert(erldns_zone_records_typed, Entry) end, Entries).

%% Expects record labels to be already reduced
-spec put_zone_records_typed_entry(generation(), dns:labels(), [dns:rr()]) -> ok.
put_zone_records_typed_entry(Gen, ReducedLabels, Records) ->
    put_zone_records([
        {{Gen, ReducedLabels, Type}, RRSet}
     || Type := RRSet <- build_typed_index(Records)
    ]).

-compile({inline, [make_improper_list/1]}).
make_improper_list(List) ->
    % eqwalizer:ignore this needs to be an improper list for tree traversal
    List ++ '_'.

%% Classify how a name exists in the zone.
%% Gen: the generation holding the zone's records
%% RecordLabels: zone-order path within zone (e.g. ["a", "b", "c"] for c.b.a.example.com)
zone_name_existence_1(Gen, RecordLabels) ->
    case pattern_zone_dname_exists(Gen, RecordLabels) of
        true ->
            exact;
        false ->
            case pattern_zone_dname_exists(Gen, make_improper_list(RecordLabels)) of
                true ->
                    ent;
                false ->
                    check_wildcard_existence(Gen, lists:reverse(RecordLabels))
            end
    end.

%% Climb parent path looking for a wildcard match.
%% PathReversed is in query order (outermost label first) so dropping the head gives the parent.
%% At each step: if the current path is an ENT, the wildcard is blocked (RFC 4592 §2.2.2, §3.3.1),
%% so we skip to the next parent. Otherwise check for a wildcard at the parent level.
%% We use lists:reverse/2 to build zone-order paths for ETS without a separate traversal.
check_wildcard_existence(_Gen, []) ->
    nxdomain;
check_wildcard_existence(Gen, [_ | ParentReversed] = PathReversed) ->
    ZoneOrderPath = lists:reverse(PathReversed),
    case pattern_zone_dname_exists(Gen, make_improper_list(ZoneOrderPath)) of
        true ->
            %% Current path is an ENT — wildcard blocked at this level, climb further
            check_wildcard_existence(Gen, ParentReversed);
        false ->
            case pattern_zone_dname_exists(Gen, lists:reverse(ParentReversed, [~"*"])) of
                true ->
                    wildcard;
                false ->
                    check_wildcard_existence(Gen, ParentReversed)
            end
    end.

%% Single-pass resolved: exact -> fetch at node; ent -> ent; else wildcard climb with single fetch.
%% When Type =:= '_', fetch all types at path (no filter). When Type =/= '_', use typed fetch;
%% if typed fetch returns [] we need one exists check to distinguish
%% "node missing" from "node, no RR of type".
get_records_resolved_1(Gen, RecordLabels, Type) ->
    case fetch_records(Gen, RecordLabels, Type) of
        [_ | _] = Records ->
            {exact, Records};
        [] when Type =/= '_' ->
            %% Typed query returned nothing — check if the node itself exists (NOERROR, no data)
            case pattern_zone_dname_exists(Gen, RecordLabels) of
                true -> {exact, []};
                false -> exact_missing_ent_or_wildcard(Gen, RecordLabels, Type)
            end;
        [] ->
            %% Untyped query returned nothing — node doesn't exist for this name
            exact_missing_ent_or_wildcard(Gen, RecordLabels, Type)
    end.

exact_missing_ent_or_wildcard(Gen, RecordLabels, Type) ->
    HasDescendantsPath = make_improper_list(RecordLabels),
    case pattern_zone_dname_exists(Gen, HasDescendantsPath) of
        true ->
            ent;
        false ->
            get_records_resolved_wildcard_1(Gen, RecordLabels, Type)
    end.

%% Climb parent path looking for wildcard records.
%% At each level: if current path is an ENT, skip (RFC 4592).
%% Otherwise check for wildcard at parent.
%% For typed lookups: if the wildcard node exists but has no records of Type, return [] (NOERROR).
get_records_resolved_wildcard_1(_Gen, [], _Type) ->
    nxdomain;
get_records_resolved_wildcard_1(Gen, RecordLabels, Type) ->
    Parent = lists:droplast(RecordLabels),
    case pattern_zone_dname_exists(Gen, make_improper_list(RecordLabels)) of
        true ->
            %% Current path is an ENT — wildcard blocked, climb further
            get_records_resolved_wildcard_1(Gen, Parent, Type);
        false ->
            WildcardPath = Parent ++ [~"*"],
            WildcardRrs = fetch_records(Gen, WildcardPath, Type),
            case WildcardRrs of
                [_ | _] ->
                    {wildcard, WildcardRrs};
                [] ->
                    case pattern_zone_dname_exists(Gen, WildcardPath) of
                        true ->
                            %% Wildcard node exists but no records of requested type
                            {wildcard, []};
                        false ->
                            get_records_resolved_wildcard_1(Gen, Parent, Type)
                    end
            end
    end.

%% record paths shall not cross the zone boundary,
%% hence we can cut the zone labels from the record labels
reduce_record_labels(ZoneLabels, RecordLabels) when is_list(ZoneLabels), is_list(RecordLabels) ->
    match_labels(lists:reverse(ZoneLabels), lists:reverse(RecordLabels)).

reduce_record_labels_pre_reversed(ReversedZoneLabels, RecordLabels) when
    is_list(ReversedZoneLabels), is_list(RecordLabels)
->
    match_labels(ReversedZoneLabels, lists:reverse(RecordLabels)).

match_labels([], Rest) ->
    Rest;
match_labels([Label | ZoneLabels], [Label | RecordLabels]) ->
    match_labels(ZoneLabels, RecordLabels);
match_labels([_ | _], [_ | _]) ->
    false.

%% expects name to be already normalized
is_name_in_any_zone_helper(Gen, []) ->
    pattern_zone_dname_exists(Gen, []);
is_name_in_any_zone_helper(Gen, [_ | ParentLabels] = RecordLabels) ->
    pattern_zone_dname_exists(Gen, RecordLabels) orelse
        is_name_in_any_zone_helper(Gen, ParentLabels).

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

find_authoritative_zone_in_cache_ds([_ | Tail] = Labels) ->
    case find_authoritative_zone_in_cache(Tail) of
        #zone{authority = [_ | _]} = Zone ->
            Zone;
        _ ->
            case ets:lookup(erldns_zones_table, Labels) of
                [#zone{authority = [_ | _]} = Zone] ->
                    Zone;
                _ ->
                    not_authoritative
            end
    end.

do_get_delegations(Name, Labels) ->
    case find_zone_generation(Labels) of
        zone_not_found ->
            [];
        {ZoneLabels, Gen} ->
            RecordLabels = reduce_record_labels(ZoneLabels, Labels),
            Records = pattern_zone_dname_type(Gen, RecordLabels, ?DNS_TYPE_NS),
            lists:filter(erldns_records:match_delegation(Name), Records)
    end.

%% expects name to be already normalized
%% A positive return of this fuction implies that the zone exists and is a parent of the given name
-spec find_zone_generation(dns:labels()) -> zone_not_found | {dns:labels(), generation()}.
find_zone_generation([]) ->
    zone_not_found;
find_zone_generation([_ | Tail] = Labels) ->
    case ets:lookup_element(erldns_zones_table, Labels, #zone.gen, zone_not_found) of
        zone_not_found ->
            find_zone_generation(Tail);
        Gen when is_integer(Gen) ->
            {Labels, Gen}
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
    maps:groups_from_list(fun(R) -> dns_domain:to_lower(R#dns_rr.name) end, Records).

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
            ZoneRRSigRecords,
    Zone#zone{
        record_count = length(Records),
        records = Records
    }.

% Sign RRSet
-spec sign_rrset(erldns:zone()) -> [dns:rr()].
sign_rrset(Zone) ->
    erldns_dnssec:get_signed_zone_records(Zone).

%% Split the RRSIG records at a name into those covering the given type and the rest.
-spec partition_rrsigs(erldns:zone(), dns:labels(), dns:type()) -> {[dns:rr()], [dns:rr()]}.
partition_rrsigs(Zone, Labels, TypeCovered) ->
    lists:partition(
        erldns_records:match_type_covered(TypeCovered),
        get_records_by_name_and_type(Zone, Labels, ?DNS_TYPE_RRSIG)
    ).

record_name_in_zone_with_descendants(Gen, QLabels) ->
    HasDescendantsPath = make_improper_list(QLabels),
    pattern_zone_dname(Gen, HasDescendantsPath).

%% Checks if there is a wildcard record matching all the way to the last label.
record_name_in_zone_with_wildcard(_, []) ->
    [];
record_name_in_zone_with_wildcard(Gen, QLabels) ->
    Parent = lists:droplast(QLabels),
    WildcardPath = Parent ++ [~"*"],
    case pattern_zone_dname(Gen, WildcardPath) of
        [] ->
            record_name_in_zone_with_wildcard(Gen, Parent);
        RRsWild ->
            RRsWild
    end.

% Find the best match records for the given QName in the given zone.
% This will attempt to walk through the domain hierarchy in the QName
% looking for both exact and wildcard matches.
record_name_in_zone_with_wildcard_strict(_, []) ->
    [];
record_name_in_zone_with_wildcard_strict(Gen, [_ | _] = RecordLabels) ->
    Parent = lists:droplast(RecordLabels),
    WildcardLabels = Parent ++ [~"*"],
    case pattern_zone_dname(Gen, WildcardLabels) of
        [] ->
            case pattern_zone_dname(Gen, Parent) of
                [] ->
                    record_name_in_zone_with_wildcard_strict(Gen, Parent);
                RRsStrict ->
                    RRsStrict
            end;
        RRsWild ->
            RRsWild
    end.

pattern_zone(Gen) ->
    Pattern = {{{Gen, '_', '_'}, '$1'}, [], ['$1']},
    lists:append(ets:select(erldns_zone_records_typed, [Pattern])).

pattern_zone_dname(Gen, Labels) ->
    Pattern = {{{Gen, Labels, '_'}, '$1'}, [], ['$1']},
    lists:append(ets:select(erldns_zone_records_typed, [Pattern])).

pattern_zone_dname_type(Gen, Labels, Type) ->
    Pattern = {{{Gen, Labels, Type}, '$1'}, [], ['$1']},
    lists:append(ets:select(erldns_zone_records_typed, [Pattern])).

pattern_zone_dname_exists(Gen, Labels) ->
    Pattern = {{{Gen, Labels, '_'}, '_'}, [], [true]},
    case ets:select(erldns_zone_records_typed, [Pattern], 1) of
        {[true], _Continuation} ->
            true;
        '$end_of_table' ->
            false
    end.

fetch_records(Gen, Labels, '_') ->
    pattern_zone_dname(Gen, Labels);
fetch_records(Gen, Labels, Type) ->
    pattern_zone_dname_type(Gen, Labels, Type).

pattern_zone_dname_type_delete(Gen, Labels, Type) ->
    Pattern = {{{Gen, Labels, Type}, '_'}, [], [true]},
    ets:select_delete(erldns_zone_records_typed, [Pattern]).

%% Taking the staging entry first means a commit racing this one either published the zone already
%% or will find it gone.
drop_abandoned({Gen, ZoneLabels}) ->
    case ets:take(erldns_staged_zones, Gen) of
        [_] ->
            ?LOG_WARNING(
                #{what => staged_zone_dropped, zone => dns_domain:join(ZoneLabels, fqdn)},
                ?LOG_METADATA
            ),
            drop_generation(Gen);
        [] ->
            ok
    end.

drop_generation(Gen) ->
    Pattern = {{{Gen, '_', '_'}, '_'}, [], [true]},
    ets:select_delete(erldns_zone_records_typed, [Pattern]).

delete_zone_sync_counters(ZoneLabels) ->
    Pattern = {{{ZoneLabels, '_', '_'}, '_'}, [], [true]},
    ets:select_delete(erldns_sync_counters, [Pattern]).

-doc false.
-spec start_link() -> term().
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, noargs, [{hibernate_after, 0}]).

-doc false.
-spec init(noargs) -> {ok, owners()}.
init(noargs) ->
    create_ets_table(erldns_zones_table, set, #zone.labels),
    create_ets_table(erldns_zone_records_typed, ordered_set),
    create_ets_table(erldns_sync_counters, set),
    create_ets_table(erldns_staged_zones, set),
    {ok, #{}}.

-doc false.
-spec handle_call(dynamic(), gen_server:from(), owners()) ->
    {reply, not_implemented, owners()}.
handle_call(Call, From, State) ->
    ?LOG_INFO(#{what => unexpected_call, from => From, call => Call}, ?LOG_METADATA),
    {reply, not_implemented, State}.

-doc false.
-spec handle_cast(dynamic(), owners()) -> {noreply, owners()}.
handle_cast({watch, Owner}, Owners) when is_map_key(Owner, Owners) ->
    {noreply, Owners};
handle_cast({watch, Owner}, Owners) ->
    {noreply, Owners#{Owner => erlang:monitor(process, Owner)}};
handle_cast(Cast, State) ->
    ?LOG_INFO(#{what => unexpected_cast, cast => Cast}, ?LOG_METADATA),
    {noreply, State}.

-doc false.
-spec handle_info(dynamic(), owners()) -> {noreply, owners()}.
handle_info({drop_generation, Gen}, State) ->
    drop_generation(Gen),
    {noreply, State};
handle_info({'DOWN', _Ref, process, Owner, _Reason}, Owners) ->
    Staged = ets:select(erldns_staged_zones, [{{'$1', '$2', Owner}, [], [{{'$1', '$2'}}]}]),
    lists:foreach(fun drop_abandoned/1, Staged),
    {noreply, maps:remove(Owner, Owners)};
handle_info(Info, State) ->
    ?LOG_INFO(#{what => unexpected_info, info => Info}, ?LOG_METADATA),
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
