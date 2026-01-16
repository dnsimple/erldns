-module(erldns_zone_decoder).
-moduledoc false.

-include_lib("dns_erlang/include/dns.hrl").
-include_lib("kernel/include/logger.hrl").
-include_lib("erldns/include/erldns.hrl").
-include_lib("public_key/include/public_key.hrl").
-define(LOG_METADATA, #{domain => [erldns, zones, decoder]}).

-export([decode/2, decode_record/2, parse_keysets/1]).

-ifdef(TEST).
-export([json_record_to_erlang/1]).
-endif.

-spec decode(json:decode_value(), [erldns_zone_codec:decoder()]) -> erldns:zone().
decode(#{~"name" := Name, ~"records" := JsonRecords} = Zone, Decoders) ->
    Sha = maps:get(~"sha", Zone, ~""),
    JsonKeys = maps:get(~"keys", Zone, []),
    Records = lists:map(fun(JsonRecord) -> decode_record(JsonRecord, Decoders) end, JsonRecords),
    FilteredRecords = lists:filter(record_filter(), Records),
    DistinctRecords = lists:usort(FilteredRecords),
    erldns_zone_codec:build_zone(Name, Sha, DistinctRecords, parse_keysets(JsonKeys)).

-spec decode_record(#{binary() => json:decode_value()}, [erldns_zone_codec:decoder()]) ->
    not_implemented | dns:rr().
decode_record(JsonRecord, Decoders) ->
    maybe
        true ?= apply_context_options(JsonRecord),
        not_implemented ?= json_record_to_erlang(JsonRecord),
        not_implemented ?= try_custom_decoders(JsonRecord, Decoders),
        ?LOG_WARNING(#{what => unsupported_record, record => JsonRecord}, ?LOG_METADATA),
        not_implemented
    else
        false ->
            not_implemented;
        Value ->
            Value
    end.

-spec parse_keysets([json:decode_value()]) -> [erldns:keyset()].
parse_keysets([]) ->
    [];
parse_keysets(JsonKeys) ->
    parse_keysets(JsonKeys, []).

% RFC4034: §3.1.5.  Signature Expiration and Inception Fields
%    The Signature Expiration and Inception field values specify a date
%    and time in the form of a 32-bit unsigned number of seconds elapsed
%    since 1 January 1970 00:00:00 UTC, ignoring leap seconds, in network
%    byte order.
parse_keysets([], Keys) ->
    Keys;
parse_keysets([Key | Rest], Keys) ->
    KeySet =
        #keyset{
            key_signing_key = to_crypto_key(maps:get(~"ksk", Key)),
            key_signing_key_tag = maps:get(~"ksk_keytag", Key),
            key_signing_alg = maps:get(~"ksk_alg", Key),
            zone_signing_key = to_crypto_key(maps:get(~"zsk", Key)),
            zone_signing_key_tag = maps:get(~"zsk_keytag", Key),
            zone_signing_alg = maps:get(~"zsk_alg", Key),
            inception = calendar:rfc3339_to_system_time(
                binary_to_list(maps:get(~"inception", Key)), [{unit, second}]
            ),
            valid_until = calendar:rfc3339_to_system_time(
                binary_to_list(maps:get(~"until", Key)), [{unit, second}]
            )
        },
    parse_keysets(Rest, [KeySet | Keys]).

to_crypto_key(KeyBin) ->
    DecodedKey = public_key:pem_entry_decode(lists:last(public_key:pem_decode(KeyBin))),
    extract_key(DecodedKey).

extract_key(#'RSAPrivateKey'{publicExponent = E, modulus = M, privateExponent = N}) ->
    [E, M, N];
extract_key(#'ECPrivateKey'{privateKey = Key, parameters = {namedCurve, ?'secp256r1'}}) ->
    Key;
extract_key(#'ECPrivateKey'{privateKey = Key, parameters = {namedCurve, ?'secp384r1'}}) ->
    Key;
extract_key(#'ECPrivateKey'{privateKey = Key, parameters = {namedCurve, ?'id-Ed25519'}}) ->
    Key;
extract_key(#'ECPrivateKey'{privateKey = Key, parameters = {namedCurve, ?'id-Ed448'}}) ->
    Key.

record_filter() ->
    fun(R) -> R =/= not_implemented end.

%% Determine if a record should be used in this name server's context.
%%
%% If the context is undefined then the record will always be used.
%%
%% If the context is a list and has at least one condition that passes
%% then it will be included in the zone
-spec apply_context_options(dynamic()) -> boolean().
apply_context_options(#{~"context" := Context}) ->
    case application:get_env(erldns, zones, #{}) of
        #{context_options := ContextOptions} when is_map(ContextOptions) ->
            apply_context_match_empty_check(
                maps:get(match_empty, ContextOptions, false), Context
            ) orelse
                apply_context_list_check(
                    maps:get(allow, ContextOptions, []), Context
                );
        _ ->
            true
    end;
apply_context_options(#{}) ->
    true.

-spec apply_context_list_check(list(), list()) -> boolean().
apply_context_list_check(ContextAllow, Context) ->
    ContextSet = sets:from_list(Context, [{version, 2}]),
    ContextAllowSet = sets:from_list(ContextAllow, [{version, 2}]),
    0 =/= sets:size(sets:intersection(ContextAllowSet, ContextSet)).

-spec apply_context_match_empty_check(true | dynamic(), [dynamic()]) -> boolean().
apply_context_match_empty_check(true, []) ->
    true;
apply_context_match_empty_check(_, _) ->
    false.

try_custom_decoders(_, []) ->
    not_implemented;
try_custom_decoders(Data, [Decoder | Rest]) ->
    case Decoder(Data) of
        not_implemented ->
            try_custom_decoders(Data, Rest);
        Record ->
            Record
    end.

% Internal converters
-spec json_record_to_erlang(dynamic()) -> not_implemented | dns:rr().
json_record_to_erlang(#{~"data" := null} = Record) ->
    ?LOG_WARNING(#{what => error_parsing_record, record => Record}, ?LOG_METADATA),
    not_implemented;
json_record_to_erlang(#{~"name" := Name, ~"type" := ~"SOA", ~"ttl" := Ttl, ~"data" := Data}) ->
    #dns_rr{
        name = Name,
        type = ?DNS_TYPE_SOA,
        data =
            #dns_rrdata_soa{
                mname = maps:get(~"mname", Data),
                rname = maps:get(~"rname", Data),
                serial = maps:get(~"serial", Data),
                refresh = maps:get(~"refresh", Data),
                retry = maps:get(~"retry", Data),
                expire = maps:get(~"expire", Data),
                minimum = maps:get(~"minimum", Data)
            },
        ttl = Ttl
    };
json_record_to_erlang(#{~"name" := Name, ~"type" := ~"NS", ~"ttl" := Ttl, ~"data" := Data}) ->
    #dns_rr{
        name = Name,
        type = ?DNS_TYPE_NS,
        data = #dns_rrdata_ns{dname = maps:get(~"dname", Data)},
        ttl = Ttl
    };
json_record_to_erlang(#{~"name" := Name, ~"type" := ~"A", ~"ttl" := Ttl, ~"data" := Data}) ->
    case inet_parse:address(binary_to_list(maps:get(~"ip", Data))) of
        {ok, Address} ->
            #dns_rr{
                name = Name,
                type = ?DNS_TYPE_A,
                data = #dns_rrdata_a{ip = Address},
                ttl = Ttl
            };
        {error, Reason} ->
            ?LOG_ERROR(
                #{
                    what => error_parsing_record,
                    name => Name,
                    type => ~"A",
                    data => Data,
                    reason => Reason
                },
                ?LOG_METADATA
            ),
            not_implemented
    end;
json_record_to_erlang(#{~"name" := Name, ~"type" := ~"AAAA", ~"ttl" := Ttl, ~"data" := Data}) ->
    case inet_parse:address(binary_to_list(maps:get(~"ip", Data))) of
        {ok, Address} ->
            #dns_rr{
                name = Name,
                type = ?DNS_TYPE_AAAA,
                data = #dns_rrdata_aaaa{ip = Address},
                ttl = Ttl
            };
        {error, Reason} ->
            ?LOG_ERROR(
                #{
                    what => error_parsing_record,
                    name => Name,
                    type => ~"AAAA",
                    data => Data,
                    reason => Reason
                },
                ?LOG_METADATA
            ),
            not_implemented
    end;
json_record_to_erlang(#{~"name" := Name, ~"type" := ~"CAA", ~"ttl" := Ttl, ~"data" := Data}) ->
    #dns_rr{
        name = Name,
        type = ?DNS_TYPE_CAA,
        data =
            #dns_rrdata_caa{
                flags = maps:get(~"flags", Data),
                tag = maps:get(~"tag", Data),
                value = maps:get(~"value", Data)
            },
        ttl = Ttl
    };
json_record_to_erlang(#{~"name" := Name, ~"type" := ~"CNAME", ~"ttl" := Ttl, ~"data" := Data}) ->
    #dns_rr{
        name = Name,
        type = ?DNS_TYPE_CNAME,
        data = #dns_rrdata_cname{dname = maps:get(~"dname", Data)},
        ttl = Ttl
    };
json_record_to_erlang(#{~"name" := Name, ~"type" := ~"MX", ~"ttl" := Ttl, ~"data" := Data}) ->
    #dns_rr{
        name = Name,
        type = ?DNS_TYPE_MX,
        data = #dns_rrdata_mx{
            exchange = maps:get(~"exchange", Data), preference = maps:get(~"preference", Data)
        },
        ttl = Ttl
    };
json_record_to_erlang(#{~"name" := Name, ~"type" := ~"HINFO", ~"ttl" := Ttl, ~"data" := Data}) ->
    #dns_rr{
        name = Name,
        type = ?DNS_TYPE_HINFO,
        data = #dns_rrdata_hinfo{cpu = maps:get(~"cpu", Data), os = maps:get(~"os", Data)},
        ttl = Ttl
    };
json_record_to_erlang(#{~"name" := Name, ~"type" := ~"RP", ~"ttl" := Ttl, ~"data" := Data}) ->
    #dns_rr{
        name = Name,
        type = ?DNS_TYPE_RP,
        data = #dns_rrdata_rp{mbox = maps:get(~"mbox", Data), txt = maps:get(~"txt", Data)},
        ttl = Ttl
    };
json_record_to_erlang(#{
    ~"name" := Name, ~"type" := ~"TXT", ~"ttl" := Ttl, ~"data" := #{~"txts" := Txts}
}) when is_list(Txts) ->
    #dns_rr{name = Name, type = ?DNS_TYPE_TXT, data = #dns_rrdata_txt{txt = Txts}, ttl = Ttl};
json_record_to_erlang(#{~"name" := Name, ~"type" := ~"PTR", ~"ttl" := Ttl, ~"data" := Data}) ->
    #dns_rr{
        name = Name,
        type = ?DNS_TYPE_PTR,
        data = #dns_rrdata_ptr{dname = maps:get(~"dname", Data)},
        ttl = Ttl
    };
json_record_to_erlang(#{
    ~"name" := Name,
    ~"type" := Type = ~"SSHFP",
    ~"ttl" := Ttl,
    ~"data" := Data
}) ->
    %% This function call may crash. Handle it as a bad record.
    try binary:decode_hex(maps:get(~"fp", Data)) of
        Fp ->
            #dns_rr{
                name = Name,
                type = ?DNS_TYPE_SSHFP,
                data =
                    #dns_rrdata_sshfp{
                        alg = maps:get(~"alg", Data),
                        fp_type = maps:get(~"fptype", Data),
                        fp = Fp
                    },
                ttl = Ttl
            }
    catch
        Class:Reason ->
            ?LOG_ERROR(
                #{
                    what => error_parsing_record,
                    name => Name,
                    type => Type,
                    data => Data,
                    class => Class,
                    reason => Reason
                },
                ?LOG_METADATA
            ),
            not_implemented
    end;
json_record_to_erlang(#{~"name" := Name, ~"type" := ~"SRV", ~"ttl" := Ttl, ~"data" := Data}) ->
    #dns_rr{
        name = Name,
        type = ?DNS_TYPE_SRV,
        data =
            #dns_rrdata_srv{
                priority = maps:get(~"priority", Data),
                weight = maps:get(~"weight", Data),
                port = maps:get(~"port", Data),
                target = maps:get(~"target", Data)
            },
        ttl = Ttl
    };
json_record_to_erlang(#{~"name" := Name, ~"type" := ~"NAPTR", ~"ttl" := Ttl, ~"data" := Data}) ->
    #dns_rr{
        name = Name,
        type = ?DNS_TYPE_NAPTR,
        data =
            #dns_rrdata_naptr{
                order = maps:get(~"order", Data),
                preference = maps:get(~"preference", Data),
                flags = maps:get(~"flags", Data),
                services = maps:get(~"services", Data),
                regexp = maps:get(~"regexp", Data),
                replacement = maps:get(~"replacement", Data)
            },
        ttl = Ttl
    };
json_record_to_erlang(#{
    ~"name" := Name,
    ~"type" := Type = ~"DS",
    ~"ttl" := Ttl,
    ~"data" := Data
}) ->
    try binary:decode_hex(maps:get(~"digest", Data)) of
        Digest ->
            #dns_rr{
                name = Name,
                type = ?DNS_TYPE_DS,
                data =
                    #dns_rrdata_ds{
                        keytag = maps:get(~"keytag", Data),
                        alg = maps:get(~"alg", Data),
                        digest_type = maps:get(~"digest_type", Data),
                        digest = Digest
                    },
                ttl = Ttl
            }
    catch
        Class:Reason ->
            ?LOG_ERROR(
                #{
                    what => error_parsing_record,
                    name => Name,
                    type => Type,
                    data => Data,
                    class => Class,
                    reason => Reason
                },
                ?LOG_METADATA
            ),
            not_implemented
    end;
json_record_to_erlang(#{
    ~"name" := Name,
    ~"type" := Type = ~"TLSA",
    ~"ttl" := Ttl,
    ~"data" := Data
}) ->
    try binary:decode_hex(maps:get(~"certificate", Data)) of
        Certificate ->
            #dns_rr{
                name = Name,
                type = ?DNS_TYPE_TLSA,
                data =
                    #dns_rrdata_tlsa{
                        usage = maps:get(~"usage", Data),
                        selector = maps:get(~"selector", Data),
                        matching_type = maps:get(~"matching_type", Data),
                        certificate = Certificate
                    },
                ttl = Ttl
            }
    catch
        Class:Reason ->
            ?LOG_ERROR(
                #{
                    what => error_parsing_record,
                    name => Name,
                    type => Type,
                    data => Data,
                    class => Class,
                    reason => Reason
                },
                ?LOG_METADATA
            ),
            not_implemented
    end;
json_record_to_erlang(#{
    ~"name" := Name,
    ~"type" := Type = ~"CDS",
    ~"ttl" := Ttl,
    ~"data" := Data
}) ->
    try binary:decode_hex(maps:get(~"digest", Data)) of
        Digest ->
            #dns_rr{
                name = Name,
                type = ?DNS_TYPE_CDS,
                data =
                    #dns_rrdata_cds{
                        keytag = maps:get(~"keytag", Data),
                        alg = maps:get(~"alg", Data),
                        digest_type = maps:get(~"digest_type", Data),
                        digest = Digest
                    },
                ttl = Ttl
            }
    catch
        Class:Reason ->
            ?LOG_ERROR(
                #{
                    what => error_parsing_record,
                    name => Name,
                    type => Type,
                    data => Data,
                    class => Class,
                    reason => Reason
                },
                ?LOG_METADATA
            ),
            not_implemented
    end;
json_record_to_erlang(#{
    ~"name" := Name, ~"type" := Type = ~"DNSKEY", ~"ttl" := Ttl, ~"data" := Data
}) ->
    try base64:decode(maps:get(~"public_key", Data)) of
        PublicKey ->
            dnssec:add_keytag_to_dnskey(#dns_rr{
                name = Name,
                type = ?DNS_TYPE_DNSKEY,
                data =
                    #dns_rrdata_dnskey{
                        flags = maps:get(~"flags", Data),
                        protocol = maps:get(~"protocol", Data),
                        alg = maps:get(~"alg", Data),
                        public_key = PublicKey,
                        keytag = 0
                    },
                ttl = Ttl
            })
    catch
        Class:Reason ->
            ?LOG_ERROR(
                #{
                    what => error_parsing_record,
                    name => Name,
                    type => Type,
                    data => Data,
                    class => Class,
                    reason => Reason
                },
                ?LOG_METADATA
            ),
            not_implemented
    end;
json_record_to_erlang(#{
    ~"name" := Name, ~"type" := Type = ~"CDNSKEY", ~"ttl" := Ttl, ~"data" := Data
}) ->
    try base64:decode(maps:get(~"public_key", Data)) of
        PublicKey ->
            dnssec:add_keytag_to_cdnskey(#dns_rr{
                name = Name,
                type = ?DNS_TYPE_CDNSKEY,
                data =
                    #dns_rrdata_cdnskey{
                        flags = maps:get(~"flags", Data),
                        protocol = maps:get(~"protocol", Data),
                        alg = maps:get(~"alg", Data),
                        public_key = PublicKey,
                        keytag = 0
                    },
                ttl = Ttl
            })
    catch
        Class:Reason ->
            ?LOG_ERROR(
                #{
                    what => error_parsing_record,
                    name => Name,
                    type => Type,
                    data => Data,
                    class => Class,
                    reason => Reason
                },
                ?LOG_METADATA
            ),
            not_implemented
    end;
json_record_to_erlang(#{~"name" := Name, ~"type" := ~"SVCB", ~"ttl" := Ttl, ~"data" := Data}) ->
    #dns_rr{
        name = Name,
        type = ?DNS_TYPE_SVCB,
        data =
            #dns_rrdata_svcb{
                svc_priority = maps:get(~"svc_priority", Data),
                target_name = maps:get(~"target_name", Data),
                svc_params = parse_svcb_params(maps:get(~"svc_params", Data, #{}))
            },
        ttl = Ttl
    };
json_record_to_erlang(#{~"name" := Name, ~"type" := ~"HTTPS", ~"ttl" := Ttl, ~"data" := Data}) ->
    #dns_rr{
        name = Name,
        type = ?DNS_TYPE_HTTPS,
        data =
            #dns_rrdata_https{
                svc_priority = maps:get(~"svc_priority", Data),
                target_name = maps:get(~"target_name", Data),
                svc_params = parse_svcb_params(maps:get(~"svc_params", Data, #{}))
            },
        ttl = Ttl
    };
json_record_to_erlang(#{
    ~"name" := Name,
    ~"type" := Type = ~"OPENPGPKEY",
    ~"ttl" := Ttl,
    ~"data" := Data
}) ->
    try base64:decode(maps:get(~"data", Data)) of
        PgpData ->
            #dns_rr{
                name = Name,
                type = ?DNS_TYPE_OPENPGPKEY,
                data = #dns_rrdata_openpgpkey{data = PgpData},
                ttl = Ttl
            }
    catch
        Class:Reason ->
            ?LOG_ERROR(
                #{
                    what => error_parsing_record,
                    name => Name,
                    type => Type,
                    data => Data,
                    class => Class,
                    reason => Reason
                },
                ?LOG_METADATA
            ),
            not_implemented
    end;
json_record_to_erlang(#{
    ~"name" := Name,
    ~"type" := Type = ~"SMIMEA",
    ~"ttl" := Ttl,
    ~"data" := Data
}) ->
    try binary:decode_hex(maps:get(~"certificate", Data)) of
        Certificate ->
            #dns_rr{
                name = Name,
                type = ?DNS_TYPE_SMIMEA,
                data =
                    #dns_rrdata_smimea{
                        usage = maps:get(~"usage", Data),
                        selector = maps:get(~"selector", Data),
                        matching_type = maps:get(~"matching_type", Data),
                        certificate = Certificate
                    },
                ttl = Ttl
            }
    catch
        Class:Reason ->
            ?LOG_ERROR(
                #{
                    what => error_parsing_record,
                    name => Name,
                    type => Type,
                    data => Data,
                    class => Class,
                    reason => Reason
                },
                ?LOG_METADATA
            ),
            not_implemented
    end;
json_record_to_erlang(#{~"name" := Name, ~"type" := ~"URI", ~"ttl" := Ttl, ~"data" := Data}) ->
    #dns_rr{
        name = Name,
        type = ?DNS_TYPE_URI,
        data =
            #dns_rrdata_uri{
                priority = maps:get(~"priority", Data),
                weight = maps:get(~"weight", Data),
                target = maps:get(~"target", Data)
            },
        ttl = Ttl
    };
json_record_to_erlang(#{
    ~"name" := Name,
    ~"type" := Type = ~"WALLET",
    ~"ttl" := Ttl,
    ~"data" := Data
}) ->
    try base64:decode(maps:get(~"data", Data)) of
        WalletData ->
            #dns_rr{
                name = Name,
                type = ?DNS_TYPE_WALLET,
                data = #dns_rrdata_wallet{data = WalletData},
                ttl = Ttl
            }
    catch
        Class:Reason ->
            ?LOG_ERROR(
                #{
                    what => error_parsing_record,
                    name => Name,
                    type => Type,
                    data => Data,
                    class => Class,
                    reason => Reason
                },
                ?LOG_METADATA
            ),
            not_implemented
    end;
json_record_to_erlang(#{
    ~"name" := Name,
    ~"type" := Type = ~"EUI48",
    ~"ttl" := Ttl,
    ~"data" := Data
}) ->
    try
        AddressHex = maps:get(~"address", Data),
        AddressBin = binary:decode_hex(AddressHex),
        case byte_size(AddressBin) of
            6 ->
                <<Address:48>> = AddressBin,
                #dns_rr{
                    name = Name,
                    type = ?DNS_TYPE_EUI48,
                    data = #dns_rrdata_eui48{address = <<Address:48>>},
                    ttl = Ttl
                };
            _ ->
                ?LOG_ERROR(
                    #{
                        what => error_parsing_record,
                        name => Name,
                        type => Type,
                        data => Data,
                        reason => invalid_eui48_length
                    },
                    ?LOG_METADATA
                ),
                not_implemented
        end
    catch
        Class:Reason ->
            ?LOG_ERROR(
                #{
                    what => error_parsing_record,
                    name => Name,
                    type => Type,
                    data => Data,
                    class => Class,
                    reason => Reason
                },
                ?LOG_METADATA
            ),
            not_implemented
    end;
json_record_to_erlang(#{
    ~"name" := Name,
    ~"type" := Type = ~"EUI64",
    ~"ttl" := Ttl,
    ~"data" := Data
}) ->
    try
        AddressHex = maps:get(~"address", Data),
        AddressBin = binary:decode_hex(AddressHex),
        case byte_size(AddressBin) of
            8 ->
                <<Address:64>> = AddressBin,
                #dns_rr{
                    name = Name,
                    type = ?DNS_TYPE_EUI64,
                    data = #dns_rrdata_eui64{address = <<Address:64>>},
                    ttl = Ttl
                };
            _ ->
                ?LOG_ERROR(
                    #{
                        what => error_parsing_record,
                        name => Name,
                        type => Type,
                        data => Data,
                        reason => invalid_eui64_length
                    },
                    ?LOG_METADATA
                ),
                not_implemented
        end
    catch
        Class:Reason ->
            ?LOG_ERROR(
                #{
                    what => error_parsing_record,
                    name => Name,
                    type => Type,
                    data => Data,
                    class => Class,
                    reason => Reason
                },
                ?LOG_METADATA
            ),
            not_implemented
    end;
json_record_to_erlang(#{~"name" := Name, ~"type" := ~"CSYNC", ~"ttl" := Ttl, ~"data" := Data}) ->
    #dns_rr{
        name = Name,
        type = ?DNS_TYPE_CSYNC,
        data =
            #dns_rrdata_csync{
                soa_serial = maps:get(~"soa_serial", Data),
                flags = maps:get(~"flags", Data),
                types = maps:get(~"types", Data, [])
            },
        ttl = Ttl
    };
json_record_to_erlang(#{~"name" := Name, ~"type" := ~"DSYNC", ~"ttl" := Ttl, ~"data" := Data}) ->
    #dns_rr{
        name = Name,
        type = ?DNS_TYPE_DSYNC,
        data =
            #dns_rrdata_dsync{
                rrtype = maps:get(~"rrtype", Data),
                scheme = maps:get(~"scheme", Data),
                port = maps:get(~"port", Data),
                target = maps:get(~"target", Data)
            },
        ttl = Ttl
    };
json_record_to_erlang(#{
    ~"name" := Name,
    ~"type" := Type = ~"ZONEMD",
    ~"ttl" := Ttl,
    ~"data" := Data
}) ->
    try binary:decode_hex(maps:get(~"hash", Data)) of
        Hash ->
            #dns_rr{
                name = Name,
                type = ?DNS_TYPE_ZONEMD,
                data =
                    #dns_rrdata_zonemd{
                        serial = maps:get(~"serial", Data),
                        scheme = maps:get(~"scheme", Data),
                        algorithm = maps:get(~"algorithm", Data),
                        hash = Hash
                    },
                ttl = Ttl
            }
    catch
        Class:Reason ->
            ?LOG_ERROR(
                #{
                    what => error_parsing_record,
                    name => Name,
                    type => Type,
                    data => Data,
                    class => Class,
                    reason => Reason
                },
                ?LOG_METADATA
            ),
            not_implemented
    end;
json_record_to_erlang(#{}) ->
    not_implemented.

%% Helper function to parse SVCB service parameters from JSON
-spec parse_svcb_params(map()) -> dns:svcb_svc_params().
parse_svcb_params(Params) when is_map(Params) ->
    SvcParams = parse_svcb_params(maps:to_list(Params), #{}),
    validate_mandatory_params(SvcParams).

-spec parse_svcb_params([{binary(), term()}], dns:svcb_svc_params()) -> dns:svcb_svc_params().
parse_svcb_params([], Acc) ->
    Acc;
parse_svcb_params([{Key, Value} | Rest], Acc) ->
    ParamKey = dns_names:name_svcb_param(Key),
    NewAcc =
        case ParamKey of
            undefined ->
                %% Unknown parameter key, skip it
                Acc;
            ?DNS_SVCB_PARAM_MANDATORY when is_list(Value) ->
                KeyNums = [dns_names:name_svcb_param(K) || K <- Value],
                Acc#{ParamKey => KeyNums};
            ?DNS_SVCB_PARAM_ALPN when is_list(Value) ->
                Acc#{ParamKey => Value};
            ?DNS_SVCB_PARAM_NO_DEFAULT_ALPN when Value =:= <<"none">> orelse Value =:= none ->
                Acc#{ParamKey => none};
            ?DNS_SVCB_PARAM_PORT when is_integer(Value) ->
                Acc#{ParamKey => Value};
            ?DNS_SVCB_PARAM_ECH when is_binary(Value) ->
                Acc#{ParamKey => Value};
            ?DNS_SVCB_PARAM_IPV4HINT when is_list(Value) ->
                IPs = [parse_ipv4(IP) || IP <- Value],
                Acc#{ParamKey => IPs};
            ?DNS_SVCB_PARAM_IPV6HINT when is_list(Value) ->
                IPs = [parse_ipv6(IP) || IP <- Value],
                Acc#{ParamKey => IPs};
            _ ->
                %% Unknown value format, skip it
                Acc
        end,
    parse_svcb_params(Rest, NewAcc).

-spec parse_ipv4(binary() | string()) -> inet:ip4_address().
parse_ipv4(IP) when is_binary(IP) ->
    parse_ipv4(binary_to_list(IP));
parse_ipv4(IP) when is_list(IP) ->
    case inet_parse:address(IP) of
        {ok, {A, B, C, D}} -> {A, B, C, D};
        _ -> throw({invalid_ipv4, IP})
    end.

-spec parse_ipv6(binary() | string()) -> inet:ip6_address().
parse_ipv6(IP) when is_binary(IP) ->
    parse_ipv6(binary_to_list(IP));
parse_ipv6(IP) when is_list(IP) ->
    case inet_parse:address(IP) of
        {ok, {A, B, C, D, E, F, G, H}} -> {A, B, C, D, E, F, G, H};
        _ -> throw({invalid_ipv6, IP})
    end.

%% Validate mandatory parameter self-consistency
%% RFC 9460: Keys listed in mandatory parameter must exist in SvcParams
%% and mandatory (key 0) cannot reference itself
-spec validate_mandatory_params(dns:svcb_svc_params()) -> dns:svcb_svc_params() | no_return().
validate_mandatory_params(#{?DNS_SVCB_PARAM_MANDATORY := MandatoryKeys} = SvcParams) ->
    %% Check that mandatory doesn't reference itself (key 0)
    case lists:member(?DNS_SVCB_PARAM_MANDATORY, MandatoryKeys) of
        true ->
            Reason = {mandatory_self_reference, ?DNS_SVCB_PARAM_MANDATORY},
            throw({svcb_mandatory_validation_error, Reason});
        false ->
            %% Check that all mandatory keys exist in SvcParams
            MissingKeys = [K || K <- MandatoryKeys, not maps:is_key(K, SvcParams)],
            case MissingKeys of
                [] ->
                    SvcParams;
                _ ->
                    Reason = {missing_mandatory_keys, MissingKeys},
                    throw({svcb_mandatory_validation_error, Reason})
            end
    end;
validate_mandatory_params(SvcParams) ->
    SvcParams.
