-module(erldns_dnssec).
-moduledoc """
DNSSEC implementation.

If you want to enable DNSSEC, you need to add this module to the packet pipeline _after_ a resolver,
that being an authoritative (e.g. `m:erldns_resolver`) or recursive
(e.g. `m:erldns_resolver_recursive`).

You also need to provide the zone keys for signing, during loading,
see [`ZONES`](priv/zones/ZONES.md) for more details.

## NSEC type-mapper extension

When a name only carries a custom type (e.g. a record that another pipeline stage synthesizes into
A/CNAME at query time), the authenticated-denial NSEC record for that name must still advertise the
_standard_ types the client will actually receive, or validating resolvers reject the answer. A
mapper widens the NSEC type bitmap accordingly.

A mapper is a `fun((RecordType, QType) -> [Type])` implementing the `c:nsec_rr_type_mapper/2`
callback. To register one, the owning pipeline stage calls `add_nsec_type_mapper/3` from its own
`c:erldns_pipeline:prepare/1`:

```erlang
prepare(Opts) ->
    erldns_dnssec:add_nsec_type_mapper(Opts, [?CUSTOM_TYPE], fun ?MODULE:nsec_rr_type_mapper/2).
```
""".

-include_lib("dns_erlang/include/dns.hrl").
-include_lib("kernel/include/logger.hrl").
-include_lib("erldns/include/erldns.hrl").

-behaviour(erldns_pipeline).

-export([prepare/1, call/2, deps/0]).
-export([get_signed_records/1, get_signed_zone_records/1]).
-export([rrsig_for_zone_rrset/2]).
-export([add_nsec_type_mapper/3]).

-ifdef(TEST).
-export([handle/7, requires_key_signing_key/1, choose_signer_for_rrset/2, find_unique_lookups/1]).
-export([map_nsec_rr_types/3]).
-endif.

-doc """
NSEC type-mapper extension callback.

Pipeline stages that introduce custom record types (e.g. ALIAS) implement this to widen the NSEC
type bitmap: given a record type present at a name and the query type, return the standard DNS types
the custom type should be advertised as. The mapper is registered into the pipeline opts with
`add_nsec_type_mapper/3` from the stage's `c:erldns_pipeline:prepare/1`.
""".
-callback nsec_rr_type_mapper(RecordType :: dns:type(), QType :: dns:type()) -> [dns:type()].
-optional_callbacks([nsec_rr_type_mapper/2]).

-type nsec_type_mapper_fun() :: fun((dns:type(), dns:type()) -> [dns:type()]).
-type nsec_type_mappers() :: #{dns:type() => nsec_type_mapper_fun()}.
-export_type([nsec_type_mappers/0, nsec_type_mapper_fun/0]).

-define(NEXT_DNAME_PART, <<"\000">>).
-define(LOG_METADATA, #{domain => [erldns, pipeline, dnssec]}).

-doc "`c:erldns_pipeline:deps/0` callback.".
-spec deps() -> erldns_pipeline:deps().
deps() ->
    #{prerequisites => [erldns_questions, erldns_resolver]}.

-doc "`c:erldns_pipeline:prepare/1` callback.".
-spec prepare(erldns_pipeline:opts()) -> erldns_pipeline:opts().
prepare(Opts) ->
    Opts#{dnssec => false, nsec_type_mappers => maps:get(nsec_type_mappers, Opts, #{})}.

-doc """
Register an NSEC type mapper for the given record types into the pipeline opts.

Extension pipes call this from their own `c:erldns_pipeline:prepare/1`. Because every pipe's
`prepare/1` contributes to the single, shared pipeline opts that is later merged into every query,
the mappers are available to this module's `call/2` at run-time as a plain map lookup — no global
registry, no process hop.
""".
-spec add_nsec_type_mapper(erldns_pipeline:opts(), [dns:type()], nsec_type_mapper_fun()) ->
    erldns_pipeline:opts().
add_nsec_type_mapper(Opts, RecordTypes, Fun) when is_function(Fun, 2) ->
    Mappers0 = maps:get(nsec_type_mappers, Opts, #{}),
    Mappers1 = lists:foldl(fun(T, Acc) -> Acc#{T => Fun} end, Mappers0, RecordTypes),
    Opts#{nsec_type_mappers => Mappers1}.

-doc "`c:erldns_pipeline:call/2` callback.".
-spec call(dns:message(), erldns_pipeline:opts()) -> erldns_pipeline:return().
call(
    #dns_message{} = Msg,
    #{
        resolved := true,
        query_name := QName,
        query_type := QType,
        query_labels := QLabels,
        auth_zone := #zone{} = Zone,
        nsec_type_mappers := Mappers
    } = Opts
) ->
    RequestDnssec = proplists:get_bool(dnssec, erldns_edns:get_opts(Msg)),
    Opts1 = Opts#{dnssec => RequestDnssec},
    {handle(Msg, Zone, QLabels, QName, QType, Mappers, RequestDnssec), Opts1};
call(Msg, Opts) ->
    RequestDnssec = proplists:get_bool(dnssec, erldns_edns:get_opts(Msg)),
    {Msg, Opts#{dnssec => RequestDnssec}}.

-doc "Get signed records from a zone".
-spec get_signed_records(erldns:zone()) -> #{atom() => [dns:rr()]}.
get_signed_records(#zone{name = ZoneName, records = Records, keysets = Keysets}) ->
    {ZoneRecords, KeyRecords} = lists:partition(fun filter_cds_cdnskey/1, Records),
    KeyRRSigRecords = lists:flatmap(key_rrset_signer(ZoneName, KeyRecords), Keysets),
    ZoneRRSigRecords = lists:flatmap(zone_rrset_signer(ZoneName, ZoneRecords), Keysets),
    #{key_rrsig_rrs => KeyRRSigRecords, zone_rrsig_rrs => ZoneRRSigRecords}.

-doc "Get signed records from a zone".
-spec get_signed_zone_records(erldns:zone()) -> [dns:rr()].
get_signed_zone_records(#zone{name = ZoneName, records = Records, keysets = Keysets}) ->
    ZoneRecords = lists:filter(fun filter_cds_cdnskey/1, Records),
    lists:flatmap(zone_rrset_signer(ZoneName, ZoneRecords), Keysets).

filter_cds_cdnskey(#dns_rr{type = Type}) ->
    (Type =/= ?DNS_TYPE_DS) andalso
        (Type =/= ?DNS_TYPE_CDS) andalso
        (Type =/= ?DNS_TYPE_DNSKEY) andalso
        (Type =/= ?DNS_TYPE_CDNSKEY).

-doc "Given a zone and a set of records, return the RRSIG records.".
-spec rrsig_for_zone_rrset(erldns:zone(), [dns:rr()]) -> [dns:rr()].
rrsig_for_zone_rrset(Zone, RRs) ->
    lists:flatmap(choose_signer_for_rrset(Zone#zone.name, RRs), Zone#zone.keysets).

-doc """
Return a function that can be used to sign the given records using the key signing key.

The function accepts a keyset, allowing the zone signing mechanism to iterate through available
keysets, applying the key signing key from each keyset.
""".
-spec key_rrset_signer(dns:dname(), [dns:rr()]) -> fun((erldns:keyset()) -> [dns:rr()]).
key_rrset_signer(ZoneName, RRs) ->
    fun(Keyset) ->
        Keytag = Keyset#keyset.key_signing_key_tag,
        Alg = Keyset#keyset.key_signing_alg,
        PrivateKey = Keyset#keyset.key_signing_key,
        Inception = Keyset#keyset.inception,
        Expiration = Keyset#keyset.valid_until,
        dnssec:sign_rr(RRs, dns_domain:to_lower(ZoneName), Keytag, Alg, PrivateKey, #{
            inception => Inception, expiration => Expiration
        })
    end.

-doc """
Return a function that can be used to sign the given records using the zone signing key.

The function accepts a keyset, allowing the zone signing mechanism to iterate through available
keysets, applying the zone signing key from each keyset.
""".
-spec zone_rrset_signer(dns:dname(), [dns:rr()]) -> fun((erldns:keyset()) -> [dns:rr()]).
zone_rrset_signer(ZoneName, RRs) ->
    fun(Keyset) ->
        Keytag = Keyset#keyset.zone_signing_key_tag,
        Alg = Keyset#keyset.zone_signing_alg,
        PrivateKey = Keyset#keyset.zone_signing_key,
        Inception = Keyset#keyset.inception,
        Expiration = Keyset#keyset.valid_until,
        dnssec:sign_rr(RRs, dns_domain:to_lower(ZoneName), Keytag, Alg, PrivateKey, #{
            inception => Inception, expiration => Expiration
        })
    end.

-doc """
Choose the appropriate signer function based on record types.

CDS and CDNSKEY records should be signed with key-signing-key, others with zone-signing-key.
""".
-spec choose_signer_for_rrset(dns:dname(), [dns:rr()]) -> fun((erldns:keyset()) -> [dns:rr()]).
choose_signer_for_rrset(ZoneName, RRs) ->
    case requires_key_signing_key(RRs) of
        true ->
            key_rrset_signer(ZoneName, RRs);
        false ->
            zone_rrset_signer(ZoneName, RRs)
    end.

-doc """
Check if any record in the set requires key-signing-key for RRSIG.

CDS and CDNSKEY records should be signed with key-signing-key.
""".
-spec requires_key_signing_key([dns:rr()]) -> boolean().
requires_key_signing_key(RRs) ->
    lists:any(
        fun(#dns_rr{type = Type}) ->
            (Type =:= ?DNS_TYPE_CDS) orelse (Type =:= ?DNS_TYPE_CDNSKEY)
        end,
        RRs
    ).

%%% Internal functions
-spec handle(Msg, Zone, QLabels, QName, QType, Mappers, RequestDnssec) -> Return when
    Msg :: dns:message(),
    Zone :: erldns:zone(),
    QLabels :: dns:labels(),
    QName :: dns:dname(),
    QType :: dns:type(),
    Mappers :: nsec_type_mappers(),
    RequestDnssec :: boolean(),
    Return :: dns:message().
%% DNSSEC not requested, leave
handle(Msg, _, _, _, _, _, false) ->
    Msg;
%% compact-denial-of-existence §3.5: Responses to explicit queries for NXNAME
handle(Msg, _, _, _, ?DNS_TYPE_NXNAME, _, _) ->
    Msg#dns_message{rc = ?DNS_RCODE_FORMERR, authority = []};
%% DNSSEC requested, zone unsigned, nothing to do
handle(Msg, #zone{keysets = []}, _, _, _, _, _) ->
    Msg;
%% DNSSEC requested, zone signed, no answers found, return NSEC.
handle(#dns_message{answers = []} = Msg, Zone, QLabels, QName, QType, Mappers, _) ->
    #dns_message{authority = MsgAuths} = Msg,
    #zone{labels = ZLabels, authority = [Authority | _]} = Zone,
    Ttl = minimum_soa_ttl(Authority),
    ApexRRSigRRs = erldns_zone_cache:get_records_by_name_and_type(Zone, ZLabels, ?DNS_TYPE_RRSIG),
    SoaRRSigRecords = maybe_get_soa_rrsig_records(ApexRRSigRRs, MsgAuths),
    RecordTypesForQname = record_types_for_name(Zone, QLabels),
    NsecRrTypes = map_nsec_rr_types(QType, RecordTypesForQname, Mappers),
    NextDname = <<?NEXT_DNAME_PART/binary, ".", QName/binary>>,
    NsecRecord =
        #dns_rr{
            name = QName,
            type = ?DNS_TYPE_NSEC,
            ttl = Ttl,
            data = #dns_rrdata_nsec{
                next_dname = NextDname,
                types = NsecRrTypes
            }
        },
    NsecRRSigRecords = rrsig_for_zone_rrset(Zone, [NsecRecord]),
    Auth = lists:append([MsgAuths, [NsecRecord], SoaRRSigRecords, NsecRRSigRecords]),
    Msg1 = Msg#dns_message{ad = true, rc = ?DNS_RCODE_NOERROR, authority = Auth},
    sign_unsigned(Msg1, Zone);
%% DNSSEC requested, zone signed, answers ready and need signing
handle(Msg, Zone, _, _, _, _, _) ->
    ?LOG_DEBUG(#{what => dnssec_requested, name => Zone#zone.name}, ?LOG_METADATA),
    AnswerSignatures = find_rrsigs(Zone, Msg#dns_message.answers),
    AuthoritySignatures = find_rrsigs(Zone, Msg#dns_message.authority),
    Msg1 = Msg#dns_message{
        ad = true,
        answers = Msg#dns_message.answers ++ AnswerSignatures,
        authority = Msg#dns_message.authority ++ AuthoritySignatures
    },
    sign_unsigned(Msg1, Zone).

% Find RRSIG record in Apex RRSIG records covering SOA record,
% but only if SOA is in the Authority Section to begin with
-spec maybe_get_soa_rrsig_records([dns:rr()], [dns:rr()]) -> [dns:rr()].
maybe_get_soa_rrsig_records(ApexRRSigRecords, MsgAuths) ->
    case lists:any(fun erldns_records:is_soa/1, MsgAuths) of
        true -> lists:filter(fun erldns_records:is_soa_rrsig/1, ApexRRSigRecords);
        false -> []
    end.

% Find all RRSIG records that cover the records in the provided record list.
-spec find_rrsigs(erldns:zone(), [dns:rr()]) -> [dns:rr()].
find_rrsigs(Zone, MessageRecords) ->
    UniqueLookups = find_unique_lookups(MessageRecords),
    lists:flatmap(
        fun(#dns_rr{name = Name, type = Type}) ->
            NamedRRSigs = erldns_zone_cache:get_records_by_name_and_type(
                Zone, Name, ?DNS_TYPE_RRSIG
            ),
            lists:filter(erldns_records:match_type_covered(Type), NamedRRSigs)
        end,
        UniqueLookups
    ).

-spec find_unique_lookups([dns:rr()]) -> [dns:rr()].
find_unique_lookups(MessageRecords) ->
    lists:usort(
        fun(#dns_rr{name = N1, type = T1}, #dns_rr{name = N2, type = T2}) ->
            (N1 < N2) orelse (N1 =:= N2 andalso T1 =< T2)
        end,
        MessageRecords
    ).

-spec sign_unsigned(dns:message(), erldns:zone()) -> dns:message().
sign_unsigned(Message, Zone) ->
    UnsignedAnswers = find_unsigned_records(Message#dns_message.answers),
    AnswerSignatures = rrsig_for_zone_rrset(Zone, UnsignedAnswers),
    Message#dns_message{answers = Message#dns_message.answers ++ AnswerSignatures}.

-spec find_unsigned_records([dns:rr()]) -> [dns:rr()].
find_unsigned_records(Records) ->
    lists:filter(
        fun(RR) ->
            (RR#dns_rr.type =/= ?DNS_TYPE_RRSIG) andalso
                (lists:filter(
                    erldns_records:match_name_and_type(RR#dns_rr.name, ?DNS_TYPE_RRSIG), Records
                ) =:= [])
        end,
        Records
    ).

%% compact-denial-of-existence-07
%%
%% Find the best match records for the given QName in the given zone.
%% This will look for both exact and wildcard matches AT the QNAME label count
%% without attempting to walk down to the root.
record_types_for_name(Zone, QLabels) ->
    %% The literal type lists are kept in ascending DNS type-code order
    %% (RRSIG=46 < NSEC=47 < NXNAME=128), so they are already sorted as the
    %% NSEC bitmap requires and need no run-time sort.
    case erldns_zone_cache:get_records_by_name_resolved(Zone, QLabels) of
        ent ->
            [?DNS_TYPE_RRSIG, ?DNS_TYPE_NSEC];
        nxdomain ->
            [?DNS_TYPE_RRSIG, ?DNS_TYPE_NSEC, ?DNS_TYPE_NXNAME];
        {_, RecordsAtName} ->
            types_covered_from_records(RecordsAtName)
    end.

types_covered_from_records(RecordsAtName) ->
    TypesCovered = lists:map(fun(RR) -> RR#dns_rr.type end, RecordsAtName),
    lists:usort([?DNS_TYPE_RRSIG, ?DNS_TYPE_NSEC | TypesCovered]).

%% Widen the NSEC type bitmap for any custom record types present at the name, using the mappers
%% frozen into the pipeline opts by extension pipes (see `add_nsec_type_mapper/3`).
-spec map_nsec_rr_types(dns:type(), [dns:type()], nsec_type_mappers()) -> [dns:type()].
map_nsec_rr_types(_QType, Types, Mappers) when map_size(Mappers) =:= 0 ->
    Types;
map_nsec_rr_types(QType, Types, Mappers) ->
    lists:usort(
        lists:flatmap(
            fun(Type) ->
                case Mappers of
                    #{Type := Fun} -> Fun(Type, QType);
                    _ -> [Type]
                end
            end,
            Types
        )
    ).

-compile({inline, [minimum_soa_ttl/1]}).
-spec minimum_soa_ttl(dns:rr()) -> dns:ttl().
minimum_soa_ttl(#dns_rr{type = ?DNS_TYPE_SOA, ttl = Rec, data = #dns_rrdata_soa{minimum = Min}}) ->
    erlang:min(Min, Rec).
