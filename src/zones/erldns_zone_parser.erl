-module(erldns_zone_parser).
-moduledoc false.

-include_lib("dns_erlang/include/dns.hrl").
-include_lib("kernel/include/logger.hrl").
-include_lib("erldns/include/erldns.hrl").

-export([decode/2]).

-ifdef(TEST).
-export([json_record_to_erlang/1, parse_keysets/1]).
-endif.

-spec decode(json:decode_value(), [erldns_zone_codec:decoder()]) -> erldns:zone().
decode(#{~"name" := Name, ~"records" := JsonRecords} = Zone, Decoders) ->
    Sha = maps:get(~"sha", Zone, ~""),
    JsonKeys = maps:get(~"keys", Zone, []),
    Records =
        lists:map(
            fun(JsonRecord) ->
                maybe
                    true ?= apply_context_options(JsonRecord),
                    not_implemented ?= json_record_to_erlang(JsonRecord),
                    not_implemented ?= try_custom_decoders(JsonRecord, Decoders),
                    ?LOG_WARNING(
                        #{what => unsupported_record, record => JsonRecord},
                        #{domain => [erldns, zones]}
                    ),
                    not_implemented
                else
                    false ->
                        not_implemented;
                    Value ->
                        Value
                end
            end,
            JsonRecords
        ),
    FilteredRecords = lists:filter(record_filter(), Records),
    DistinctRecords = lists:usort(FilteredRecords),
    erldns_zone_codec:build_zone(Name, Sha, DistinctRecords, parse_keysets(JsonKeys)).

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

to_crypto_key(RsaKeyBin) ->
    % Where E is the public exponent, N is public modulus and D is the private exponent
    [_, _, M, E, N | _] = tuple_to_list(
        public_key:pem_entry_decode(lists:last(public_key:pem_decode(RsaKeyBin)))
    ),
    [E, M, N].

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
    case application:get_env(erldns, context_options) of
        {ok, ContextOptions} when is_map(ContextOptions) ->
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
    ?LOG_WARNING(#{what => error_parsing_record, record => Record}, #{domain => [erldns, zones]}),
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
                #{domain => [erldns, zones]}
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
                #{domain => [erldns, zones]}
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
json_record_to_erlang(#{
    ~"name" := Name, ~"type" := ~"SPF", ~"ttl" := Ttl, ~"data" := #{~"txts" := Txts}
}) when is_list(Txts) ->
    #dns_rr{name = Name, type = ?DNS_TYPE_SPF, data = #dns_rrdata_spf{spf = Txts}, ttl = Ttl};
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
                #{domain => [erldns, zones]}
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
                #{domain => [erldns, zones]}
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
                #{domain => [erldns, zones]}
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
                #{domain => [erldns, zones]}
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
                #{domain => [erldns, zones]}
            ),
            not_implemented
    end;
json_record_to_erlang(#{}) ->
    not_implemented.
