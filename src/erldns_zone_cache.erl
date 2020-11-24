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

%% @doc A cache holding all of the zone data.
%%
%% Write operations occur through the cache process mailbox, whereas read
%% operations may occur either through the mailbox or directly through the
%% underlying data store, depending on performance requirements.
-module(erldns_zone_cache).

-behavior(gen_server).

-include_lib("dns_erlang/include/dns.hrl").

-include("erldns.hrl").

-export([start_link/0]).
% Read APIs
-export([find_zone/1,
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
         get_rrset_sync_counter/3]).
% Deprecated APIs
-export([get_zone_with_records/1]).
% Write APIs
-export([put_zone/1,
         put_zone/2,
         delete_zone/1,
         update_zone_records_and_digest/3,
         put_zone_rrset/4,
         delete_zone_rrset/5]).
% Gen server hooks
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

-define(SERVER, ?MODULE).

-record(state, {parsers, tref = none}).

%% @doc Start the zone cache process.
-spec start_link() -> any().
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

% ----------------------------------------------------------------------------------------------------
% Read API

%% @doc Find a zone for a given qname.
-spec find_zone(dns:dname()) -> #zone{} | {error, zone_not_found} | {error, not_authoritative}.
find_zone(Qname) ->
    find_zone(erldns:normalize_name(Qname), get_authority(Qname)).

%% @doc Find a zone for a given qname.
-spec find_zone(dns:dname(), {error, any()} | {ok, dns:rr()} | [dns:rr()] | dns:rr()) ->
                   #zone{} | {error, zone_not_found} | {error, not_authoritative}.
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

%% @doc Get a zone for the specific name. This function will not attempt to resolve
%% the dname in any way, it will simply look up the name in the underlying data store.
-spec get_zone(dns:dname()) -> {ok, #zone{}} | {error, zone_not_found}.
get_zone(Name) ->
    NormalizedName = erldns:normalize_name(Name),
    case erldns_storage:select(zones, NormalizedName) of
        [{NormalizedName, Zone}] ->
            {ok,
             Zone#zone{name = NormalizedName,
                       records = [],
                       records_by_name = trimmed}};
        _ ->
            {error, zone_not_found}
    end.

%% @doc Get a zone for the specific name, including the records for the zone.
%% @deprecated Use {@link erldns_zone_cache:get_zone/1} to get the zone meta data and
%% {@link erldns_zone_cache:get_zone_records/1} to get the records for the zone.
-spec get_zone_with_records(dns:dname()) -> {ok, #zone{}} | {error, zone_not_found}.
get_zone_with_records(Name) ->
    NormalizedName = erldns:normalize_name(Name),
    case erldns_storage:select(zones, NormalizedName) of
        [{NormalizedName, Zone}] ->
            {ok, Zone};
        _ ->
            {error, zone_not_found}
    end.

%% @doc Find the SOA record for the given DNS question.
-spec get_authority(dns:message() | dns:dname()) -> {error, no_question} | {error, authority_not_found} | {ok, dns:authority()}.
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

%% @doc Get the list of NS and glue records for the given name. This function
%% will always return a list, even if it is empty.
-spec get_delegations(dns:dname()) -> [dns:rr()] | [].
get_delegations(Name) ->
    case find_zone_in_cache(Name) of
        {ok, Zone} ->
            Records =
                lists:flatten(erldns_storage:select(zone_records_typed,
                                                    [{{{erldns:normalize_name(Zone#zone.name), '_', ?DNS_TYPE_NS}, '$1'}, [], ['$$']}],
                                                    infinite)),
            lists:filter(erldns_records:match_delegation(Name), Records);
        _ ->
            []
    end.

%% @doc Get all records for the given zone.
-spec get_zone_records(dns:dname()) -> [dns:rr()].
get_zone_records(Name) ->
    case find_zone_in_cache(Name) of
        {ok, Zone} ->
            lists:flatten(erldns_storage:select(zone_records_typed, [{{{erldns:normalize_name(Zone#zone.name), '_', '_'}, '$1'}, [], ['$$']}], infinite));
        _ ->
            []
    end.

%% @doc Get all records for the given type and given name.
-spec get_records_by_name_and_type(dns:dname(), dns:type()) -> [dns:rr()].
get_records_by_name_and_type(Name, Type) ->
    case find_zone_in_cache(Name) of
        {ok, Zone} ->
            lists:flatten(erldns_storage:select(zone_records_typed,
                                                [{{{erldns:normalize_name(Zone#zone.name), erldns:normalize_name(Name), Type}, '$1'}, [], ['$$']}],
                                                infinite));
        _ ->
            []
    end.

%% @doc Get all DNSSEC records for zone
-spec get_zone_dnskey_records(dns:dname()) -> [dns:rr()].
get_zone_dnskey_records(Name) ->
    case find_zone_in_cache(Name) of
        {ok, _Zone} ->
            get_records_by_name_and_type(Name, ?DNS_TYPE_DNSKEY);
        _ ->
            []
    end.

%% @doc Return the record set for the given dname.
-spec get_records_by_name(dns:dname()) -> [dns:rr()].
get_records_by_name(Name) ->
    case find_zone_in_cache(Name) of
        {ok, Zone} ->
            lists:flatten(erldns_storage:select(zone_records_typed,
                                                [{{{erldns:normalize_name(Zone#zone.name), erldns:normalize_name(Name), '_'}, '$1'}, [], ['$$']}],
                                                infinite));
        _ ->
            []
    end.

%% @doc Check if the name is in a zone.
-spec in_zone(binary()) -> boolean().
in_zone(Name) ->
    case find_zone_in_cache(Name) of
        {ok, Zone} ->
            is_name_in_zone(Name, Zone);
        _ ->
            false
    end.

%% @doc Check if the record name is in the zone. Will also return true if a wildcard is present at the node.
-spec record_name_in_zone(binary(), dns:dname()) -> boolean().
record_name_in_zone(ZoneName, Name) ->
    case find_zone_in_cache(Name) of
        {ok, Zone} ->
            case lists:flatten(erldns_storage:select(zone_records_typed, [{{{ZoneName, erldns:normalize_name(Name), '_'}, '$1'}, [], ['$$']}], infinite)) of
                [] ->
                    is_name_in_zone_with_wildcard(Name, Zone);
                _ ->
                    true
            end;
        _ ->
            false
    end.

%% @doc Return a list of tuples with each tuple as a name and the version SHA
%% for the zone.
-spec zone_names_and_versions() -> [{dns:dname(), binary()}].
zone_names_and_versions() ->
    % ETS and Mnesia foldl/3 differ in return values -> Mnesia's version is missing key
    case erldns_config:storage_type() of
        erldns_storage_json ->
            erldns_storage:foldl(fun({_, Zone}, NamesAndShas) -> NamesAndShas ++ [{Zone#zone.name, Zone#zone.version}] end, [], zones);
        erldns_storage_mnesia ->
            erldns_storage:foldl(fun(Zone, NamesAndShas) -> NamesAndShas ++ [{Zone#zone.name, Zone#zone.version}] end, [], zones)
    end.

%% @doc Return current sync counter
-spec get_rrset_sync_counter(dns:dname(), dns:dname(), dns:type()) -> integer().
get_rrset_sync_counter(ZoneName, RRFqdn, Type) ->
    case erldns_storage:select(sync_counters, [{{erldns:normalize_name(ZoneName), erldns:normalize_name(RRFqdn), Type, '$1'}, [], ['$_']}], infinite) of
        [{ZoneName, RRFqdn, Type, Counter}] ->
            Counter;
        [] ->
            0 % return default value of 0
    end.

%% @doc Update the RRSet sync counter for the given RR set name and type in the given zone.
-spec write_rrset_sync_counter({dns:dname(), dns:dname(), dns:type(), integer()}) -> ok.
write_rrset_sync_counter({ZoneName, RRFqdn, Type, Counter}) ->
    erldns_storage:insert(sync_counters, {ZoneName, RRFqdn, Type, Counter}).

% ----------------------------------------------------------------------------------------------------
% Write API

%% @doc Put a name and its records into the cache, along with a SHA which can be
%% used to determine if the zone requires updating.
%%
%% This function will build the necessary Zone record before inserting.
-spec put_zone({Name, Sha, Records, Keys} | {Name, Sha, Records}) -> ok | {error, Reason :: term()}
    when Name :: binary(),
         Sha :: binary(),
         Records :: [dns:rr()],
         Keys :: [erldns:keyset()].
put_zone({Name, Sha, Records}) ->
    put_zone({Name, Sha, Records, []});
put_zone({Name, Sha, Records, Keys}) ->
    SignedZone = sign_zone(build_zone(Name, Sha, Records, Keys)),
    NamedRecords = build_named_index(SignedZone#zone.records),
    delete_zone_records(erldns:normalize_name(Name)),
    case put_zone(erldns:normalize_name(Name), SignedZone#zone{records = trimmed}) of
        ok ->
            put_zone_records(erldns:normalize_name(Name), NamedRecords);
        {error, Reason} ->
            {error, Reason}
    end.

%% @doc Put a zone into the cache and wait for a response.
-spec put_zone(dns:name(), erldns:zone()) -> ok | {error, Reason :: term()}.
put_zone(Name, Zone) ->
    erldns_storage:insert(zones, {erldns:normalize_name(Name), Zone}).

-spec put_zone_records(dns:name(), map()) -> ok.
put_zone_records(Name, RecordsByName) ->
    put_zone_records_entry(Name, maps:next(maps:iterator(RecordsByName))).

%% @doc Put zone RRSet
-spec put_zone_rrset({dns:dname(), binary(), [dns:rr()]} | {dns:dname(), binary(), [dns:rr()], [any()]}, dns:dname(), dns:type(), integer()) ->
                        ok | {error, Reason :: term()}.
put_zone_rrset({ZoneName, Digest, Records}, RRFqdn, Type, Counter) ->
    put_zone_rrset({ZoneName, Digest, Records, []}, RRFqdn, Type, Counter);
put_zone_rrset({ZoneName, Digest, Records, _Keys}, RRFqdn, Type, Counter) ->
    case find_zone_in_cache(erldns:normalize_name(ZoneName)) of
        {ok, Zone} ->
            % TODO: remove debug
            lager:debug("Putting RRSet (~p) with Type: ~p for Zone (~p): ~p", [RRFqdn, Type, ZoneName, Records]),
            KeySets = Zone#zone.keysets,
            DnsKeyRRs = get_zone_dnskey_records(ZoneName),
            SignedRRSet = sign_rrset(ZoneName, Records, DnsKeyRRs, KeySets),
            RRSigRecs = filter_rrsig_records_with_type_covered(RRFqdn, Type),

            % RRSet records + RRSIG records for the type + the rest of RRSIG records for FQDN
            TypedRecords = build_typed_index(Records ++ SignedRRSet ++ RRSigRecs),
            % put zone_records_typed records first then create the records in zone_records
            put_zone_records_typed_entry(ZoneName, RRFqdn, maps:next(maps:iterator(TypedRecords))),

            update_zone_records_and_digest(ZoneName, get_zone_records(ZoneName), Digest),

            write_rrset_sync_counter({ZoneName, RRFqdn, Type, Counter}),

            lager:debug("RRSet update completed for FQDN: ~p, Type: ~p", [RRFqdn, Type]),
            ok;
        _ -> % if zone is not in cache, return error
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
    erldns_storage:insert(zone_records_typed, {{erldns:normalize_name(ZoneName), erldns:normalize_name(Fqdn), K}, V}),
    put_zone_records_typed_entry(ZoneName, Fqdn, maps:next(I)).

%% @doc Remove a zone from the cache without waiting for a response.
-spec delete_zone(binary()) -> any().
delete_zone(Name) ->
    gen_server:cast(?SERVER, {delete, Name}).

-spec delete_zone_records(binary()) -> any().
delete_zone_records(Name) ->
    erldns_storage:select_delete(zone_records_typed, [{{{erldns:normalize_name(Name), '_', '_'}, '_'}, [], [true]}]).

%% @doc Remove zone RRSet
-spec delete_zone_rrset(binary(), binary(), binary(), integer(), integer()) -> any().
delete_zone_rrset(ZoneName, Digest, RRFqdn, Type, Counter) ->
    case find_zone_in_cache(erldns:normalize_name(ZoneName)) of
        {ok, Zone} ->
            Zone,
            CurrentCounter = get_rrset_sync_counter(ZoneName, RRFqdn, Type),
            case Counter of
                N when N =:= 0; CurrentCounter < N ->
                    lager:debug("Removing RRSet (~p) with type ~p", [RRFqdn, Type]),

                    erldns_storage:select_delete(zone_records_typed,
                                                 [{{{erldns:normalize_name(ZoneName), erldns:normalize_name(RRFqdn), Type}, '_'}, [], [true]}]),

                    % remove the RRSIG for the given record type
                    {_RRSigsCovering, RRSigsNotCovering} =
                        lists:partition(erldns_records:match_type_covered(Type), get_records_by_name_and_type(RRFqdn, ?DNS_TYPE_RRSIG_NUMBER)),
                    erldns_storage:insert(zone_records_typed,
                                          {{erldns:normalize_name(ZoneName), erldns:normalize_name(RRFqdn), ?DNS_TYPE_RRSIG_NUMBER}, RRSigsNotCovering}),

                    % only write counter if called explicitly with Counter value i.e. different than 0.
                    % this will not write the counter if called by put_zone_rrset/3 as it will prevent subsequent delete ops
                    case Counter of
                        N when N > 0 ->
                            % DELETE RRSet command has been sent
                            % we need to update the zone digest as the zone content changes
                            update_zone_records_and_digest(ZoneName, get_zone_records(ZoneName), Digest),

                            write_rrset_sync_counter({ZoneName, RRFqdn, Type, Counter});
                        _ ->
                            ok
                    end;
                N when CurrentCounter > N ->
                    lager:debug("Not processing delete operation for RRSet (~p): counter (~p) provided is lower than system", [RRFqdn, Counter])
            end;
        _ ->
            {error, zone_not_found}
    end.

%% @doc Given a zone name, list of records, and a digest, update the zone metadata in cache.
-spec update_zone_records_and_digest(dns:dname(), [dns:rr()], binary()) -> ok | {error, Reason :: term()}.
update_zone_records_and_digest(ZoneName, Records, Digest) ->
    case find_zone_in_cache(erldns:normalize_name(ZoneName)) of
        {ok, Zone} ->
            Zone,
            UpdatedZone =
                Zone#zone{version = Digest,
                          authority = get_records_by_name_and_type(ZoneName, ?DNS_TYPE_SOA),
                          record_count = length(Records),
                          records_by_name = build_named_index(Records)},
            put_zone(Zone#zone.name, UpdatedZone);
        _ ->
            {error, zone_not_found}
    end.

%% @doc Filter RRSig records for FQDN, removing type covered.
-spec filter_rrsig_records_with_type_covered(dns:dname(), dns:type()) -> [{{dns:dname(), dns:dname(), dns:type()}, [dns:rr()]} | []].
filter_rrsig_records_with_type_covered(Fqdn, TypeCovered) ->
    % guards below do not allow fun calls to prevent side effects
    case find_zone_in_cache(erldns:normalize_name(Fqdn)) of
        {ok, _Zone} ->
            lists:flatten(lists:foldl(fun(R, Records) ->
                                         case R#dns_rr.data#dns_rrdata_rrsig.type_covered =/= TypeCovered of
                                             true -> [R | Records];
                                             false -> [Records]
                                         end
                                      end,
                                      [],
                                      get_records_by_name_and_type(Fqdn, ?DNS_TYPE_RRSIG_NUMBER)));
        _ ->
            []
    end.

% ----------------------------------------------------------------------------------------------------
% Gen server init

%% @doc Initialize the zone cache.
-spec init([]) -> {ok, #state{}}.
init([]) ->
    erldns_storage:create(schema),
    erldns_storage:create(zones),
    erldns_storage:create(zone_records_typed),
    erldns_storage:create(authorities),
    erldns_storage:create(sync_counters),
    {ok, #state{parsers = []}}.

% ----------------------------------------------------------------------------------------------------
% gen_server callbacks

handle_call(Message, _From, State) ->
    lager:debug("Received unsupported call (message: ~p)", [Message]),
    {reply, ok, State}.

handle_cast({delete, Name}, State) ->
    erldns_storage:delete(zones, erldns:normalize_name(Name)),
    delete_zone_records(Name),
    {noreply, State};
handle_cast(Message, State) ->
    lager:debug("Received unsupported cast (message: ~p)", [Message]),
    {noreply, State}.

handle_info(_Message, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_PreviousVersion, State, _Extra) ->
    {ok, State}.

% Internal API
is_name_in_zone(Name, Zone) ->
    ZoneName = erldns:normalize_name(Zone#zone.name),
    case lists:flatten(erldns_storage:select(zone_records_typed, [{{{ZoneName, erldns:normalize_name(Name), '_'}, '$1'}, [], ['$$']}], infinite)) of
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
    case lists:flatten(erldns_storage:select(zone_records_typed, [{{{ZoneName, WildcardName, '_'}, '$1'}, [], ['$$']}], infinite)) of
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
    case erldns_storage:select(zones, Name) of
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
    #zone{name = Qname,
          version = Version,
          record_count = length(Records),
          authority = Authorities,
          records = Records,
          records_by_name = trimmed,
          keysets = Keys}.

-spec build_named_index([#dns_rr{}]) -> #{binary() => [#dns_rr{}]}.
build_named_index(Records) ->
    NamedIndex =
        lists:foldl(fun(R, Idx) ->
                       Name = erldns:normalize_name(R#dns_rr.name),
                       maps:update_with(Name, fun(RR) -> [R | RR] end, [R], Idx)
                    end,
                    #{},
                    Records),
    maps:map(fun(_K, V) -> lists:reverse(V) end, NamedIndex).

-spec build_typed_index([#dns_rr{}]) -> #{dns:type() => [#dns_rr{}]}.
build_typed_index(Records) ->
    TypedIndex = lists:foldl(fun(R, Idx) -> maps:update_with(R#dns_rr.type, fun(RR) -> [R | RR] end, [R], Idx) end, #{}, Records),
    maps:map(fun(_K, V) -> lists:reverse(V) end, TypedIndex).

-spec sign_zone(erldns:zone()) -> erldns:zone().
sign_zone(Zone = #zone{keysets = []}) ->
    Zone;
sign_zone(Zone) ->
    % lager:debug("Signing zone (name: ~p)", [Zone#zone.name]),
    DnskeyRRs = lists:filter(erldns_records:match_type(?DNS_TYPE_DNSKEY), Zone#zone.records),
    KeyRRSigRecords = lists:flatten(lists:map(erldns_dnssec:key_rrset_signer(Zone#zone.name, DnskeyRRs), Zone#zone.keysets)),
    Verify = verify_zone(Zone, DnskeyRRs, KeyRRSigRecords),
    lager:debug("Zone verified: ~p", [Verify]),
    % TODO: remove wildcard signatures as they will not be used but are taking up space
    ZoneRRSigRecords =
        lists:flatten(lists:map(erldns_dnssec:zone_rrset_signer(Zone#zone.name,
                                                                lists:filter(fun(RR) -> RR#dns_rr.type =/= ?DNS_TYPE_DNSKEY end, Zone#zone.records)),
                                Zone#zone.keysets)),
    Records =
        Zone#zone.records ++
            KeyRRSigRecords ++ rewrite_soa_rrsig_ttl(Zone#zone.records, ZoneRRSigRecords -- lists:filter(erldns_records:match_wildcard(), ZoneRRSigRecords)),
    #zone{name = Zone#zone.name,
          version = Zone#zone.version,
          record_count = length(Records),
          authority = Zone#zone.authority,
          records = Records,
          records_by_name = build_named_index(Records),
          keysets = Zone#zone.keysets}.

-spec verify_zone(erldns:zone(), [dns:rr()], [dns:rr()]) -> boolean().
verify_zone(_Zone, DnskeyRRs, KeyRRSigRecords) ->
    % lager:debug("Verify zone (name: ~p)", [Zone#zone.name]),
    case lists:filter(fun(RR) -> RR#dns_rr.data#dns_rrdata_dnskey.flags =:= ?DNSKEY_KSK_TYPE end, DnskeyRRs) of
        [] ->
            false;
        KSKs ->
            % lager:debug("KSKs: ~p", [KSKs]),
            KSKDnskey = lists:last(KSKs),
            RRSig = lists:last(KeyRRSigRecords),
            % lager:debug("Attempting to verify RRSIG (key: ~p)", [KSKDnskey]),
            VerifyResult = dnssec:verify_rrsig(RRSig, DnskeyRRs, [KSKDnskey], []),
            % lager:debug("KSK verification (verified?: ~p)", [VerifyResult]),
            VerifyResult
    end.

% Sign RRSet
-spec sign_rrset(binary(), [dns:rr()], [dns:rr()], [erldns:keyset()]) -> [dns:rr()].
sign_rrset(Name, Records, DnsKeyRRs, KeySets) ->
    % lager:debug("Signing RRSet for zone (name: ~p)", [Name]),
    KeyRRSigRecords = lists:flatten(lists:map(erldns_dnssec:key_rrset_signer(Name, DnsKeyRRs), KeySets)),
    ZoneRecords = get_zone_records(Name),
    RRSigRecords =
        rewrite_soa_rrsig_ttl(ZoneRecords,
                              lists:flatten(lists:map(erldns_dnssec:zone_rrset_signer(Name,
                                                                                      lists:filter(fun(RR) -> RR#dns_rr.type =/= ?DNS_TYPE_DNSKEY end,
                                                                                                   Records)),
                                                      KeySets))),
    verify_rrset(DnsKeyRRs, KeyRRSigRecords),
    RRSigRecords.

% Verify RRSet
-spec verify_rrset([dns:rr()], [dns:rr()]) -> boolean().
verify_rrset(DnsKeyRRs, KeyRRSigRecords) ->
    % lager:debug("Verify RRSet"),
    case lists:filter(fun(RR) -> RR#dns_rr.data#dns_rrdata_dnskey.flags =:= ?DNSKEY_KSK_TYPE end, DnsKeyRRs) of
        [] ->
            false;
        KSKs ->
            case KeyRRSigRecords of
                [] ->
                    false;
                _ ->
                    % lager:debug("KSKs: ~p", [KSKs]),
                    KSKDnskey = lists:last(KSKs),
                    RRSig = lists:last(KeyRRSigRecords),
                    VerifyResult = dnssec:verify_rrsig(RRSig, DnsKeyRRs, [KSKDnskey], []),
                    VerifyResult
            end
    end.

% Rewrite the RRSIG TTL so it follows the same rewrite rules as the SOA TTL.
rewrite_soa_rrsig_ttl(ZoneRecords, RRSigRecords) ->
    SoaRR = lists:last(lists:filter(erldns_records:match_type(?DNS_TYPE_SOA), ZoneRecords)),
    lists:map(fun(RR) ->
                 case RR#dns_rr.type of
                     ?DNS_TYPE_RRSIG ->
                         case RR#dns_rr.data#dns_rrdata_rrsig.type_covered of
                             ?DNS_TYPE_SOA -> erldns_records:minimum_soa_ttl(RR, SoaRR#dns_rr.data);
                             _ -> RR
                         end;
                     _ -> RR
                 end
              end,
              RRSigRecords).
