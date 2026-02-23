-module(erldns_dnssec).
-moduledoc """
DNSSEC implementation.

If you want to enable DNSSEC, you need to add this module to the packet pipeline _after_ a resolver,
that being an authoritative (e.g. `m:erldns_resolver`) or recursive
(e.g. `m:erldns_resolver_recursive`).

You also need to provide the zone keys for signing, during loading,
see [`ZONES`](priv/zones/ZONES.md) for more details.
""".

-include_lib("dns_erlang/include/dns.hrl").
-include_lib("kernel/include/logger.hrl").
-include_lib("erldns/include/erldns.hrl").

-behaviour(erldns_pipeline).

-export([prepare/1, call/2, deps/0]).
-export([get_signed_records/1, get_signed_zone_records/1]).
-export([rrsig_for_zone_rrset/2]).

-ifdef(TEST).
-export([handle/6, requires_key_signing_key/1, choose_signer_for_rrset/2]).
-endif.

-define(NEXT_DNAME_PART, <<"\000">>).
-define(LOG_METADATA, #{domain => [erldns, pipeline, dnssec]}).

-doc "`c:erldns_pipeline:deps/0` callback.".
-spec deps() -> erldns_pipeline:deps().
deps() ->
    #{prerequisites => [erldns_questions, erldns_resolver]}.

-doc "`c:erldns_pipeline:prepare/1` callback.".
-spec prepare(erldns_pipeline:opts()) -> erldns_pipeline:opts().
prepare(Opts) ->
    Opts#{dnssec => false}.

-doc "`c:erldns_pipeline:call/2` callback.".
-spec call(dns:message(), erldns_pipeline:opts()) -> erldns_pipeline:return().
call(
    #dns_message{} = Msg,
    #{
        resolved := true,
        query_name := QName,
        query_type := QType,
        query_labels := QLabels,
        auth_zone := #zone{} = Zone
    } = Opts
) ->
    RequestDnssec = proplists:get_bool(dnssec, erldns_edns:get_opts(Msg)),
    Opts1 = Opts#{dnssec => RequestDnssec},
    {handle(Msg, Zone, QLabels, QName, QType, RequestDnssec), Opts1};
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
-spec handle(Msg, Zone, QLabels, QName, QType, RequestDnssec) -> Return when
    Msg :: dns:message(),
    Zone :: erldns:zone(),
    QLabels :: dns:labels(),
    QName :: dns:dname(),
    QType :: dns:type(),
    RequestDnssec :: boolean(),
    Return :: dns:message().
%% DNSSEC not requested, leave
handle(Msg, _, _, _, _, false) ->
    Msg;
%% compact-denial-of-existence §3.5: Responses to explicit queries for NXNAME
handle(Msg, _, _, _, ?DNS_TYPE_NXNAME, _) ->
    Msg#dns_message{rc = ?DNS_RCODE_FORMERR, authority = []};
%% DNSSEC requested, zone unsigned, nothing to do
handle(Msg, #zone{keysets = []}, _, _, _, _) ->
    Msg;
%% DNSSEC requested, zone signed, no answers found, return NSEC.
handle(#dns_message{answers = []} = Msg, Zone, QLabels, QName, QType, _) ->
    #dns_message{authority = MsgAuths} = Msg,
    #zone{labels = ZLabels, authority = [Authority | _]} = Zone,
    Ttl = minimum_soa_ttl(Authority),
    ApexRRSigRRs = erldns_zone_cache:get_records_by_name_and_type(Zone, ZLabels, ?DNS_TYPE_RRSIG),
    SoaRRSigRecords = maybe_get_soa_rrsig_records(ApexRRSigRRs, MsgAuths),
    RecordTypesForQname = record_types_for_name(Zone, QLabels),
    NsecRrTypes = erldns_handler:call_map_nsec_rr_types(QType, RecordTypesForQname),
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
handle(Msg, Zone, _, _, _, _) ->
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
    UniqueLookups = lists:usort(
        fun(#dns_rr{name = N1, type = T1}, #dns_rr{name = N2, type = T2}) ->
            N1 =< N2 andalso T1 =< T2
        end,
        MessageRecords
    ),
    lists:flatmap(
        fun(#dns_rr{name = Name, type = Type}) ->
            NamedRRSigs = erldns_zone_cache:get_records_by_name_and_type(
                Zone, Name, ?DNS_TYPE_RRSIG
            ),
            lists:filter(erldns_records:match_type_covered(Type), NamedRRSigs)
        end,
        UniqueLookups
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
    case erldns_zone_cache:get_records_by_name_resolved(Zone, QLabels) of
        ent ->
            lists:sort([?DNS_TYPE_RRSIG, ?DNS_TYPE_NSEC]);
        nxdomain ->
            lists:sort([?DNS_TYPE_RRSIG, ?DNS_TYPE_NSEC, ?DNS_TYPE_NXNAME]);
        {_, RecordsAtName} ->
            types_covered_from_records(RecordsAtName)
    end.

types_covered_from_records(RecordsAtName) ->
    TypesCovered = lists:map(fun(RR) -> RR#dns_rr.type end, RecordsAtName),
    lists:usort([?DNS_TYPE_RRSIG, ?DNS_TYPE_NSEC | TypesCovered]).

-compile({inline, [minimum_soa_ttl/1]}).
-spec minimum_soa_ttl(dns:rr()) -> dns:ttl().
minimum_soa_ttl(#dns_rr{type = ?DNS_TYPE_SOA, ttl = Rec, data = #dns_rrdata_soa{minimum = Min}}) ->
    erlang:min(Min, Rec).
