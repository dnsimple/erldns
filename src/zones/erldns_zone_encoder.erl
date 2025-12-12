-module(erldns_zone_encoder).
-moduledoc false.

-include_lib("dns_erlang/include/dns.hrl").
-include_lib("kernel/include/logger.hrl").
-include_lib("erldns/include/erldns.hrl").

-export([encode/3]).

-spec encode(erldns:zone(), #{atom() => dynamic()}, [erldns_zone_codec:encoder()]) ->
    not_implemented | json:encode_value().
encode(Zone, #{mode := zone_records_to_json}, Encoders) ->
    encode_zone_records_to_json(Zone, Encoders);
encode(Zone, #{mode := {zone_records_to_json, RecordName}}, Encoders) ->
    encode_zone_records_to_json(Zone, RecordName, Encoders);
encode(Zone, #{mode := {zone_records_to_json, RecordName, RecordType}}, Encoders) ->
    encode_zone_records_to_json(Zone, RecordName, RecordType, Encoders);
encode(Zone, #{mode := zone_meta_to_json}, _) ->
    zone_meta_to_json(Zone);
encode(Zone, #{mode := zone_to_json}, Encoders) ->
    Records = records_to_json(Zone, Encoders),
    #{
        ~"erldns" =>
            #{
                ~"zone" => #{
                    ~"name" => Zone#zone.name,
                    ~"version" => Zone#zone.version,
                    ~"records_count" => length(Records),
                    % Note: Private key material is purposely omitted
                    ~"records" => Records
                }
            }
    }.

-spec zone_meta_to_json(erldns:zone()) -> json:encode_value().
zone_meta_to_json(Zone) ->
    #{
        ~"erldns" =>
            #{
                % Note: Private key material is purposely omitted
                ~"zone" => #{
                    ~"name" => Zone#zone.name,
                    ~"version" => Zone#zone.version,
                    ~"records_count" => Zone#zone.record_count
                }
            }
    }.

% Internal API
encode_zone_records_to_json(Zone, Encoders) ->
    Records = erldns_zone_cache:get_zone_records(Zone),
    lists:flatmap(encode(Encoders), Records).

encode_zone_records_to_json(Zone, RecordName, Encoders) ->
    Records = erldns_zone_cache:get_records_by_name(Zone, RecordName),
    lists:flatmap(encode(Encoders), Records).

encode_zone_records_to_json(Zone, RecordName, RecordType, Encoders) ->
    Type = dns_names:name_type(RecordType),
    Records = erldns_zone_cache:get_records_by_name_and_type(Zone, RecordName, Type),
    lists:flatmap(encode(Encoders), Records).

records_to_json(Zone, Encoders) ->
    lists:flatmap(encode(Encoders), erldns_zone_cache:get_zone_records(Zone)).

encode(Encoders) ->
    fun(Record) -> erlang_record_to_json(Record, Encoders) end.

erlang_record_to_json(Record, Encoders) ->
    case erlang_record_to_json(Record) of
        not_implemented ->
            try_custom_encoders(Record, Encoders);
        EncodedRecord ->
            [EncodedRecord]
    end.

erlang_record_to_json(#dns_rr{name = Name, type = Type, ttl = Ttl, data = Data}) ->
    case type_to_string(Type) of
        not_implemented ->
            not_implemented;
        TypeName ->
            case data_to_json(Type, Data) of
                not_implemented ->
                    not_implemented;
                JsonData ->
                    #{
                        ~"name" => Name,
                        ~"type" => TypeName,
                        ~"ttl" => Ttl,
                        ~"data" => JsonData
                    }
            end
    end;
erlang_record_to_json(_) ->
    not_implemented.

type_to_string(?DNS_TYPE_SOA) -> ~"SOA";
type_to_string(?DNS_TYPE_NS) -> ~"NS";
type_to_string(?DNS_TYPE_A) -> ~"A";
type_to_string(?DNS_TYPE_AAAA) -> ~"AAAA";
type_to_string(?DNS_TYPE_CAA) -> ~"CAA";
type_to_string(?DNS_TYPE_CNAME) -> ~"CNAME";
type_to_string(?DNS_TYPE_MX) -> ~"MX";
type_to_string(?DNS_TYPE_HINFO) -> ~"HINFO";
type_to_string(?DNS_TYPE_RP) -> ~"RP";
type_to_string(?DNS_TYPE_TXT) -> ~"TXT";
type_to_string(?DNS_TYPE_PTR) -> ~"PTR";
type_to_string(?DNS_TYPE_SSHFP) -> ~"SSHFP";
type_to_string(?DNS_TYPE_SRV) -> ~"SRV";
type_to_string(?DNS_TYPE_NAPTR) -> ~"NAPTR";
type_to_string(?DNS_TYPE_DS) -> ~"DS";
type_to_string(?DNS_TYPE_TLSA) -> ~"TLSA";
type_to_string(?DNS_TYPE_CDS) -> ~"CDS";
type_to_string(?DNS_TYPE_DNSKEY) -> ~"DNSKEY";
type_to_string(?DNS_TYPE_CDNSKEY) -> ~"CDNSKEY";
type_to_string(?DNS_TYPE_RRSIG) -> ~"RRSIG";
type_to_string(?DNS_TYPE_NSEC) -> ~"NSEC";
type_to_string(?DNS_TYPE_NSEC3) -> ~"NSEC3";
type_to_string(_) -> not_implemented.

data_to_json(?DNS_TYPE_SOA, #dns_rrdata_soa{
    mname = Mname,
    rname = Rname,
    serial = Serial,
    refresh = Refresh,
    retry = Retry,
    expire = Expire,
    minimum = Minimum
}) ->
    #{
        ~"mname" => Mname,
        ~"rname" => Rname,
        ~"serial" => Serial,
        ~"refresh" => Refresh,
        ~"retry" => Retry,
        ~"expire" => Expire,
        ~"minimum" => Minimum
    };
data_to_json(?DNS_TYPE_NS, #dns_rrdata_ns{dname = Dname}) ->
    #{~"dname" => Dname};
data_to_json(?DNS_TYPE_A, #dns_rrdata_a{ip = Ip}) ->
    IpString = list_to_binary(inet:ntoa(Ip)),
    #{~"ip" => IpString};
data_to_json(?DNS_TYPE_AAAA, #dns_rrdata_aaaa{ip = Ip}) ->
    IpString = list_to_binary(inet:ntoa(Ip)),
    #{~"ip" => IpString};
data_to_json(?DNS_TYPE_CAA, #dns_rrdata_caa{
    flags = Flags,
    tag = Tag,
    value = Value
}) ->
    #{
        ~"flags" => Flags,
        ~"tag" => Tag,
        ~"value" => Value
    };
data_to_json(?DNS_TYPE_CNAME, #dns_rrdata_cname{dname = Dname}) ->
    #{~"dname" => Dname};
data_to_json(?DNS_TYPE_MX, #dns_rrdata_mx{
    exchange = Exchange,
    preference = Preference
}) ->
    #{
        ~"exchange" => Exchange,
        ~"preference" => Preference
    };
data_to_json(?DNS_TYPE_HINFO, #dns_rrdata_hinfo{
    cpu = Cpu,
    os = Os
}) ->
    #{
        ~"cpu" => Cpu,
        ~"os" => Os
    };
data_to_json(?DNS_TYPE_RP, #dns_rrdata_rp{
    mbox = Mbox,
    txt = Txt
}) ->
    #{
        ~"mbox" => Mbox,
        ~"txt" => Txt
    };
data_to_json(?DNS_TYPE_TXT, #dns_rrdata_txt{txt = Txts}) ->
    #{~"txts" => Txts};
data_to_json(?DNS_TYPE_PTR, #dns_rrdata_ptr{dname = Dname}) ->
    #{~"dname" => Dname};
data_to_json(?DNS_TYPE_SSHFP, #dns_rrdata_sshfp{
    alg = Alg,
    fp_type = FpType,
    fp = Fp
}) ->
    FpHex = binary:encode_hex(Fp),
    #{
        ~"alg" => Alg,
        ~"fptype" => FpType,
        ~"fp" => FpHex
    };
data_to_json(?DNS_TYPE_SRV, #dns_rrdata_srv{
    priority = Priority,
    weight = Weight,
    port = Port,
    target = Target
}) ->
    #{
        ~"priority" => Priority,
        ~"weight" => Weight,
        ~"port" => Port,
        ~"target" => Target
    };
data_to_json(?DNS_TYPE_NAPTR, #dns_rrdata_naptr{
    order = Order,
    preference = Preference,
    flags = Flags,
    services = Services,
    regexp = Regexp,
    replacement = Replacement
}) ->
    #{
        ~"order" => Order,
        ~"preference" => Preference,
        ~"flags" => Flags,
        ~"services" => Services,
        ~"regexp" => Regexp,
        ~"replacement" => Replacement
    };
data_to_json(?DNS_TYPE_DS, #dns_rrdata_ds{
    keytag = KeyTag,
    alg = Alg,
    digest_type = DigestType,
    digest = Digest
}) ->
    DigestHex = binary:encode_hex(Digest),
    #{
        ~"keytag" => KeyTag,
        ~"alg" => Alg,
        ~"digest_type" => DigestType,
        ~"digest" => DigestHex
    };
data_to_json(?DNS_TYPE_TLSA, #dns_rrdata_tlsa{
    usage = Usage,
    selector = Selector,
    matching_type = MatchingType,
    certificate = Certificate
}) ->
    CertHex = binary:encode_hex(Certificate),
    #{
        ~"usage" => Usage,
        ~"selector" => Selector,
        ~"matching_type" => MatchingType,
        ~"certificate" => CertHex
    };
data_to_json(?DNS_TYPE_CDS, #dns_rrdata_cds{
    keytag = KeyTag,
    alg = Alg,
    digest_type = DigestType,
    digest = Digest
}) ->
    DigestHex = binary:encode_hex(Digest),
    #{
        ~"keytag" => KeyTag,
        ~"alg" => Alg,
        ~"digest_type" => DigestType,
        ~"digest" => DigestHex
    };
data_to_json(?DNS_TYPE_DNSKEY, #dns_rrdata_dnskey{
    flags = Flags,
    protocol = Protocol,
    alg = Alg,
    public_key = PublicKey,
    keytag = KeyTag
}) ->
    PublicKeyBinary = encode_dnskey_public_key(PublicKey, Alg),
    PublicKeyBase64 = base64:encode(PublicKeyBinary),
    #{
        ~"flags" => Flags,
        ~"protocol" => Protocol,
        ~"alg" => Alg,
        ~"public_key" => PublicKeyBase64,
        ~"keytag" => KeyTag
    };
data_to_json(?DNS_TYPE_CDNSKEY, #dns_rrdata_cdnskey{
    flags = Flags,
    protocol = Protocol,
    alg = Alg,
    public_key = PublicKey,
    keytag = KeyTag
}) ->
    PublicKeyBinary = encode_dnskey_public_key(PublicKey, Alg),
    PublicKeyBase64 = base64:encode(PublicKeyBinary),
    #{
        ~"flags" => Flags,
        ~"protocol" => Protocol,
        ~"alg" => Alg,
        ~"public_key" => PublicKeyBase64,
        ~"keytag" => KeyTag
    };
data_to_json(?DNS_TYPE_RRSIG, #dns_rrdata_rrsig{
    type_covered = TypeCovered,
    alg = Alg,
    labels = Labels,
    original_ttl = OriginalTtl,
    expiration = Expiration,
    inception = Inception,
    keytag = KeyTag,
    signers_name = SignersName,
    signature = Signature
}) ->
    SignatureBase64 = base64:encode(Signature),
    #{
        ~"type_covered" => TypeCovered,
        ~"alg" => Alg,
        ~"labels" => Labels,
        ~"original_ttl" => OriginalTtl,
        ~"expiration" => Expiration,
        ~"inception" => Inception,
        ~"keytag" => KeyTag,
        ~"signers_name" => SignersName,
        ~"signature" => SignatureBase64
    };
data_to_json(?DNS_TYPE_NSEC, #dns_rrdata_nsec{
    next_dname = NextDname,
    types = Types
}) ->
    #{
        ~"next_dname" => NextDname,
        ~"types" => Types
    };
data_to_json(?DNS_TYPE_NSEC3, #dns_rrdata_nsec3{
    hash_alg = HashAlgorithm,
    opt_out = Flags,
    hash = NextHashedOwnerName,
    iterations = Iterations,
    salt = Salt,
    types = Types
}) ->
    SaltHex = binary:encode_hex(Salt),
    NextHashedOwnerNameBase64 = base64:encode(NextHashedOwnerName),
    #{
        ~"hash_alg" => HashAlgorithm,
        ~"opt_out" => Flags,
        ~"iterations" => Iterations,
        ~"salt" => SaltHex,
        ~"hash" => NextHashedOwnerNameBase64,
        ~"types" => Types
    };
data_to_json(_, _) ->
    not_implemented.

%% Encode DNSKEY public key to binary format.
%% For RSA keys (alg 5 or 8), PublicKey is a list of two integers [E, M] (exponent, modulus).
%% For other algorithms, PublicKey is already a binary.
%% DNSKEY wire format for RSA, see RFC3110
-spec encode_dnskey_public_key(binary() | [integer()], integer()) -> binary().
encode_dnskey_public_key([E, M], Alg) when
    ?DNS_ALG_RSASHA1 =:= Alg orelse ?DNS_ALG_RSASHA256 =:= Alg
->
    ExponentBin = binary:encode_unsigned(E, big),
    ModulusBin = binary:encode_unsigned(M, big),
    ExponentLength = byte_size(ExponentBin),
    <<ExponentLength:8, ExponentBin/binary, ModulusBin/binary>>;
encode_dnskey_public_key(PublicKey, _) when is_binary(PublicKey) ->
    PublicKey.

try_custom_encoders(_, []) ->
    [];
try_custom_encoders(Record, [Encoder | Rest]) ->
    case Encoder(Record) of
        not_implemented ->
            try_custom_encoders(Record, Rest);
        EncodedData ->
            [EncodedData]
    end.
