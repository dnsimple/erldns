-module(erldns_zone_encoder).
-moduledoc false.

-include_lib("dns_erlang/include/dns.hrl").
-include_lib("kernel/include/logger.hrl").
-include_lib("erldns/include/erldns.hrl").

-export([encode/3]).

-spec encode(erldns:zone(), #{atom() => dynamic()}, [erldns_zone_codec:encoder()]) ->
    not_implemented | json:encode_value().
encode(Zone, #{mode := zone_meta_to_json}, _) ->
    zone_meta_to_json(Zone);
encode(Zone, #{mode := {zone_records_to_json, RecordName}}, Encoders) ->
    encode_zone_records_to_json(Zone, RecordName, Encoders);
encode(Zone, #{mode := {zone_records_to_json, RecordName, RecordType}}, Encoders) ->
    encode_zone_records_to_json(Zone, RecordName, RecordType, Encoders);
encode(Zone, #{mode := zone_to_json}, Encoders) ->
    Records = records_to_json(Zone, Encoders),
    FilteredRecords = lists:filter(record_filter(), Records),
    #{
        ~"erldns" =>
            #{
                ~"zone" => #{
                    ~"name" => Zone#zone.name,
                    ~"version" => Zone#zone.version,
                    ~"records_count" => length(FilteredRecords),
                    % Note: Private key material is purposely omitted
                    ~"records" => FilteredRecords
                }
            }
    }.

-doc "Encode a Zone meta data into JSON.".
-spec zone_meta_to_json(erldns:zone()) -> json:encode_value().
zone_meta_to_json(Zone) ->
    #{
        ~"erldns" =>
            #{
                ~"zone" => #{
                    ~"name" => Zone#zone.name,
                    ~"version" => Zone#zone.version,
                    % Note: Private key material is purposely omitted
                    ~"records_count" => length(erldns_zone_cache:get_zone_records(Zone#zone.name))
                }
            }
    }.

% Internal API
encode_zone_records_to_json(_ZoneName, RecordName, Encoders) ->
    Records = erldns_zone_cache:get_records_by_name(RecordName),
    lists:filter(record_filter(), lists:map(encode(Encoders), Records)).

encode_zone_records_to_json(_ZoneName, RecordName, RecordType, Encoders) ->
    Records = erldns_zone_cache:get_records_by_name_and_type(
        RecordName, erldns_records:name_type(RecordType)
    ),
    lists:filter(record_filter(), lists:map(encode(Encoders), Records)).

record_filter() ->
    fun(R) ->
        case R of
            not_implemented -> false;
            _ -> true
        end
    end.

records_to_json(Zone, Encoders) ->
    lists:map(encode(Encoders), erldns_zone_cache:get_zone_records(Zone#zone.name)).

encode(Encoders) ->
    fun(Record) -> encode_record(Record, Encoders) end.

encode_record(Record, Encoders) ->
    % ?LOG_DEBUG("Encoding record (record: ~p)", [Record]),
    case encode_record(Record) of
        [] ->
            % ?LOG_DEBUG("Trying custom encoders (encoders: ~p)", [Encoders]),
            try_custom_encoders(Record, Encoders);
        EncodedRecord ->
            EncodedRecord
    end.

encode_record(#dns_rr{name = Name, type = Type = ?DNS_TYPE_SOA, ttl = Ttl, data = Data}) ->
    encode_record(Name, Type, Ttl, Data);
encode_record(#dns_rr{name = Name, type = Type = ?DNS_TYPE_NS, ttl = Ttl, data = Data}) ->
    encode_record(Name, Type, Ttl, Data);
encode_record(#dns_rr{name = Name, type = Type = ?DNS_TYPE_A, ttl = Ttl, data = Data}) ->
    encode_record(Name, Type, Ttl, Data);
encode_record(#dns_rr{name = Name, type = Type = ?DNS_TYPE_AAAA, ttl = Ttl, data = Data}) ->
    encode_record(Name, Type, Ttl, Data);
encode_record(#dns_rr{name = Name, type = Type = ?DNS_TYPE_CNAME, ttl = Ttl, data = Data}) ->
    encode_record(Name, Type, Ttl, Data);
encode_record(#dns_rr{name = Name, type = Type = ?DNS_TYPE_MX, ttl = Ttl, data = Data}) ->
    encode_record(Name, Type, Ttl, Data);
encode_record(#dns_rr{name = Name, type = Type = ?DNS_TYPE_HINFO, ttl = Ttl, data = Data}) ->
    encode_record(Name, Type, Ttl, Data);
encode_record(#dns_rr{name = Name, type = Type = ?DNS_TYPE_TXT, ttl = Ttl, data = Data}) ->
    encode_record(Name, Type, Ttl, Data);
encode_record(#dns_rr{name = Name, type = Type = ?DNS_TYPE_SPF, ttl = Ttl, data = Data}) ->
    encode_record(Name, Type, Ttl, Data);
encode_record(#dns_rr{name = Name, type = Type = ?DNS_TYPE_SSHFP, ttl = Ttl, data = Data}) ->
    encode_record(Name, Type, Ttl, Data);
encode_record(#dns_rr{name = Name, type = Type = ?DNS_TYPE_SRV, ttl = Ttl, data = Data}) ->
    encode_record(Name, Type, Ttl, Data);
encode_record(#dns_rr{name = Name, type = Type = ?DNS_TYPE_NAPTR, ttl = Ttl, data = Data}) ->
    encode_record(Name, Type, Ttl, Data);
encode_record(#dns_rr{name = Name, type = Type = ?DNS_TYPE_CAA, ttl = Ttl, data = Data}) ->
    encode_record(Name, Type, Ttl, Data);
encode_record(#dns_rr{name = Name, type = Type = ?DNS_TYPE_DS, ttl = Ttl, data = Data}) ->
    encode_record(Name, Type, Ttl, Data);
encode_record(#dns_rr{name = Name, type = Type = ?DNS_TYPE_CDS, ttl = Ttl, data = Data}) ->
    encode_record(Name, Type, Ttl, Data);
encode_record(#dns_rr{name = Name, type = Type = ?DNS_TYPE_DNSKEY, ttl = Ttl, data = Data}) ->
    encode_record(Name, Type, Ttl, Data);
encode_record(#dns_rr{name = Name, type = Type = ?DNS_TYPE_CDNSKEY, ttl = Ttl, data = Data}) ->
    encode_record(Name, Type, Ttl, Data);
encode_record(#dns_rr{name = Name, type = Type = ?DNS_TYPE_RRSIG, ttl = Ttl, data = Data}) ->
    encode_record(Name, Type, Ttl, Data);
encode_record(Record) ->
    ?LOG_WARNING("Unable to encode record (record: ~p)", [Record]),
    [].

encode_record(Name, Type, Ttl, Data) ->
    #{
        ~"name" => erlang:iolist_to_binary(io_lib:format("~s.", [Name])),
        ~"type" => dns_names:type_name(Type),
        ~"ttl" => Ttl,
        ~"content" => encode_data(Data)
    }.

try_custom_encoders(_Record, []) ->
    {};
try_custom_encoders(Record, [Encoder | Rest]) ->
    % ?LOG_DEBUG("Trying custom encoder (encoder: ~p)", [Encoder]),
    case Encoder(Record) of
        [] ->
            try_custom_encoders(Record, Rest);
        EncodedData ->
            EncodedData
    end.

encode_data({dns_rrdata_soa, Mname, Rname, Serial, Refresh, Retry, Expire, Minimum}) ->
    erlang:iolist_to_binary(
        io_lib:format("~s. ~s. (~w ~w ~w ~w ~w)", [
            Mname, Rname, Serial, Refresh, Retry, Expire, Minimum
        ])
    );
encode_data({dns_rrdata_ns, Dname}) ->
    erlang:iolist_to_binary(io_lib:format("~s.", [Dname]));
encode_data({dns_rrdata_a, Address}) ->
    list_to_binary(inet_parse:ntoa(Address));
encode_data({dns_rrdata_aaaa, Address}) ->
    list_to_binary(inet_parse:ntoa(Address));
encode_data({dns_rrdata_caa, Flags, Tag, Value}) ->
    erlang:iolist_to_binary(io_lib:format("~w ~s \"~s\"", [Flags, Tag, Value]));
encode_data({dns_rrdata_cname, Dname}) ->
    erlang:iolist_to_binary(io_lib:format("~s.", [Dname]));
encode_data({dns_rrdata_mx, Preference, Dname}) ->
    erlang:iolist_to_binary(io_lib:format("~w ~s.", [Preference, Dname]));
encode_data({dns_rrdata_hinfo, Cpu, Os}) ->
    erlang:iolist_to_binary(io_lib:format("~w ~w", [Cpu, Os]));
% RP
encode_data({dns_rrdata_txt, Text}) ->
    erlang:iolist_to_binary(io_lib:format("~s", [Text]));
encode_data({dns_rrdata_spf, [Data]}) ->
    erlang:iolist_to_binary(io_lib:format("~s", [Data]));
encode_data({dns_rrdata_sshfp, Alg, Fptype, Fp}) ->
    erlang:iolist_to_binary(io_lib:format("~w ~w ~s", [Alg, Fptype, Fp]));
encode_data({dns_rrdata_srv, Priority, Weight, Port, Dname}) ->
    erlang:iolist_to_binary(io_lib:format("~w ~w ~w ~s.", [Priority, Weight, Port, Dname]));
encode_data({dns_rrdata_naptr, Order, Preference, Flags, Services, Regexp, Replacements}) ->
    erlang:iolist_to_binary(
        io_lib:format("~w ~w ~s ~s ~s ~s", [
            Order, Preference, Flags, Services, Regexp, Replacements
        ])
    );
encode_data({dns_rrdata_ds, KeyTag, Alg, DigestType, Digest}) ->
    erlang:iolist_to_binary(io_lib:format("~w ~w ~w ~s", [KeyTag, Alg, DigestType, Digest]));
encode_data({dns_rrdata_cds, KeyTag, Alg, DigestType, Digest}) ->
    erlang:iolist_to_binary(io_lib:format("~w ~w ~w ~s", [KeyTag, Alg, DigestType, Digest]));
encode_data({dns_rrdata_dnskey, Flags, Protocol, Alg, Key, KeyTag}) ->
    binary:encode_hex(
        erlang:iolist_to_binary(
            io_lib:format("~w ~w ~w ~w ~w", [Flags, Protocol, Alg, Key, KeyTag])
        )
    );
encode_data({dns_rrdata_cdnskey, Flags, Protocol, Alg, Key, KeyTag}) ->
    binary:encode_hex(
        erlang:iolist_to_binary(
            io_lib:format("~w ~w ~w ~w ~w", [Flags, Protocol, Alg, Key, KeyTag])
        )
    );
encode_data(
    {dns_rrdata_rrsig, TypeCovered, Alg, Labels, OriginalTtl, Expiration, Inception, KeyTag,
        SignersName, Signature}
) ->
    binary:encode_hex(
        erlang:iolist_to_binary(
            io_lib:format(
                "~w ~w ~w ~w ~w ~w ~w ~w ~s",
                [
                    TypeCovered,
                    Alg,
                    Labels,
                    OriginalTtl,
                    Expiration,
                    Inception,
                    KeyTag,
                    SignersName,
                    Signature
                ]
            )
        )
    );
encode_data(Data) ->
    ?LOG_INFO("Unable to encode rrdata (module: ~p, event: ~p, data: ~p)", [
        ?MODULE, unsupported_rrdata_type, Data
    ]),
    {}.
