-module(erldns_dnssec).
-moduledoc """
DNSSEC implementation.
""".

-include_lib("dns_erlang/include/dns.hrl").
-include_lib("kernel/include/logger.hrl").
-include("erldns.hrl").

-export([handle/4]).
-export([
    get_signed_records/1,
    get_signed_zone_records/1
]).
-export([maybe_sign_rrset/3, rrsig_for_zone_rrset/2]).

-ifdef(TEST).
-export([requires_key_signing_key/1, choose_signer_for_rrset/2]).
-endif.

-define(NEXT_DNAME_PART, <<"\000">>).

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

-doc " Given a zone and a set of records, return the RRSIG records.".
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
        dnssec:sign_rr(RRs, dns:dname_to_lower(ZoneName), Keytag, Alg, PrivateKey, #{
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
        dnssec:sign_rr(RRs, dns:dname_to_lower(ZoneName), Keytag, Alg, PrivateKey, #{
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
This function will potentially sign the given RR set if the following conditions are true:

- DNSSEC is requested
- The zone is signed
""".
-spec maybe_sign_rrset(dns:message(), [dns:rr()], erldns:zone()) -> [dns:rr()].
maybe_sign_rrset(Message, Records, Zone) ->
    case {proplists:get_bool(dnssec, erldns_edns:get_opts(Message)), Zone#zone.keysets} of
        {true, []} ->
            % DNSSEC requested, zone not signed
            Records;
        {true, _} ->
            % DNSSEC requested, zone signed
            Records ++ rrsig_for_zone_rrset(Zone, Records);
        {false, _} ->
            % DNSSEC not requested
            Records
    end.

-doc """
Apply DNSSEC records to the given message if the zone is signed and DNSSEC is requested.
""".
-spec handle(dns:message(), erldns:zone(), dns:dname(), dns:type()) -> dns:message().
handle(Message, Zone, Qname, QType) ->
    HasKeySets = [] =/= Zone#zone.keysets,
    RequestDnssec = proplists:get_bool(dnssec, erldns_edns:get_opts(Message)),
    handle(Message, Zone, Qname, QType, HasKeySets, RequestDnssec).

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
-spec handle(dns:message(), erldns:zone(), dns:dname(), dns:type(), boolean(), boolean()) ->
    dns:message().
handle(Msg, _, _, _, _, false) ->
    Msg;
handle(Msg, _, _, ?DNS_TYPE_NXNAME, _, true) ->
    %% compact-denial-of-existence §3.5: Responses to explicit queries for NXNAME
    Msg#dns_message{rc = ?DNS_RCODE_FORMERR, authority = []};
handle(Msg, _, _, _, false, true) ->
    % DNSSEC requested, zone unsigned, nothing to do
    Msg;
handle(#dns_message{answers = [], authority = MsgAuths} = Msg, Zone, Qname, QType, true, true) ->
    % No answers found, return NSEC.
    Authority = lists:last(Zone#zone.authority),
    Ttl = Authority#dns_rr.data#dns_rrdata_soa.minimum,
    ApexRecords = erldns_zone_cache:get_records_by_name(Zone#zone.name),
    ApexRRSigRecords = lists:filter(erldns_records:match_type(?DNS_TYPE_RRSIG), ApexRecords),
    SoaRRSigRecords = lists:filter(
        erldns_records:match_type_covered(?DNS_TYPE_SOA), ApexRRSigRecords
    ),
    NameToNormalise = dns:labels_to_dname([?NEXT_DNAME_PART | dns:dname_to_labels(Qname)]),
    NextDname = dns:dname_to_lower(NameToNormalise),
    RecordTypesForQname = record_types_for_name(Qname, Zone),
    NsecRrTypes = erldns_handler:call_map_nsec_rr_types(QType, RecordTypesForQname),
    NsecRecords =
        [
            #dns_rr{
                name = Qname,
                type = ?DNS_TYPE_NSEC,
                ttl = Ttl,
                data = #dns_rrdata_nsec{
                    next_dname = NextDname,
                    types = NsecRrTypes
                }
            }
        ],
    NsecRRSigRecords = rrsig_for_zone_rrset(Zone, NsecRecords),
    Auth = lists:append([MsgAuths, NsecRecords, SoaRRSigRecords, NsecRRSigRecords]),
    Msg1 = Msg#dns_message{
        ad = true,
        rc = ?DNS_RCODE_NOERROR,
        authority = Auth
    },
    Msg2 = sign_unsigned(Msg1, Zone),
    erldns_records:rewrite_soa_ttl(Msg2);
handle(Msg, Zone, _, _, true, true) ->
    ?LOG_DEBUG(#{what => dnssec_requested, name => Zone#zone.name}, #{domain => [erldns]}),
    AnswerSignatures = find_rrsigs(Msg#dns_message.answers),
    AuthoritySignatures = find_rrsigs(Msg#dns_message.authority),
    Msg1 = Msg#dns_message{
        ad = true,
        answers = Msg#dns_message.answers ++ AnswerSignatures,
        authority = Msg#dns_message.authority ++ AuthoritySignatures
    },
    Msg2 = sign_unsigned(Msg1, Zone),
    erldns_records:rewrite_soa_ttl(Msg2).

% Find all RRSIG records that cover the records in the provided record list.
-spec find_rrsigs([dns:rr()]) -> [dns:rr()].
find_rrsigs(MessageRecords) ->
    NamesAndTypes = lists:usort(
        lists:map(fun(RR) -> {RR#dns_rr.name, RR#dns_rr.type} end, MessageRecords)
    ),
    lists:flatmap(
        fun({Name, Type}) ->
            NamedRRSigs = erldns_zone_cache:get_records_by_name_and_type(Name, ?DNS_TYPE_RRSIG),
            lists:filter(erldns_records:match_type_covered(Type), NamedRRSigs)
        end,
        NamesAndTypes
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
            (RR#dns_rr.type =/= ?DNS_TYPE_RRSIG) and
                (lists:filter(
                    erldns_records:match_name_and_type(RR#dns_rr.name, ?DNS_TYPE_RRSIG), Records
                ) =:= [])
        end,
        Records
    ).

%% compact-denial-of-existence-07
record_types_for_name(Name, _Zone) ->
    case erldns_resolver:best_match_at_node(Name) of
        [] ->
            %% §3.1: Responses for Non-Existent Names
            lists:sort([?DNS_TYPE_RRSIG, ?DNS_TYPE_NSEC, ?DNS_TYPE_NXNAME]);
        RecordsAtName ->
            TypesCovered = lists:map(fun(RR) -> RR#dns_rr.type end, RecordsAtName),
            lists:usort([?DNS_TYPE_RRSIG, ?DNS_TYPE_NSEC | TypesCovered])
    end.
