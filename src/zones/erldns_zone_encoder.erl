-module(erldns_zone_encoder).
-moduledoc false.

-include_lib("dns_erlang/include/dns.hrl").
-include_lib("kernel/include/logger.hrl").
-include_lib("erldns/include/erldns.hrl").
-define(LOG_METADATA, #{domain => [erldns, zones, encoder]}).

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
    zone_meta_to_json(Zone, #{});
encode(Zone, #{mode := zone_to_json}, Encoders) ->
    Records = records_to_json(Zone, Encoders),
    Extra = #{~"records" => Records},
    zone_meta_to_json(Zone, Extra).

% Note: Private key material is purposely omitted
-spec zone_meta_to_json(erldns:zone(), dynamic()) -> json:encode_value().
zone_meta_to_json(Zone, MaybeRecords) ->
    Zone0 = #{
        ~"name" => Zone#zone.name,
        ~"version" => Zone#zone.version,
        ~"records_count" => Zone#zone.record_count
    },
    ZoneJson = maps:merge(Zone0, MaybeRecords),
    #{~"erldns" => #{~"zone" => ZoneJson}}.

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
    fun(Record) -> encode_record(Record, Encoders) end.

encode_record(Record, Encoders) ->
    case encode_record(Record) of
        not_implemented ->
            try_custom_encoders(Record, Encoders);
        EncodedRecord ->
            [EncodedRecord]
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
encode_record(#dns_rr{name = Name, type = Type = ?DNS_TYPE_TLSA, ttl = Ttl, data = Data}) ->
    encode_record(Name, Type, Ttl, Data);
encode_record(#dns_rr{name = Name, type = Type = ?DNS_TYPE_SVCB, ttl = Ttl, data = Data}) ->
    encode_record(Name, Type, Ttl, Data);
encode_record(#dns_rr{name = Name, type = Type = ?DNS_TYPE_HTTPS, ttl = Ttl, data = Data}) ->
    encode_record(Name, Type, Ttl, Data);
encode_record(#dns_rr{name = Name, type = Type = ?DNS_TYPE_OPENPGPKEY, ttl = Ttl, data = Data}) ->
    encode_record(Name, Type, Ttl, Data);
encode_record(#dns_rr{name = Name, type = Type = ?DNS_TYPE_SMIMEA, ttl = Ttl, data = Data}) ->
    encode_record(Name, Type, Ttl, Data);
encode_record(#dns_rr{name = Name, type = Type = ?DNS_TYPE_URI, ttl = Ttl, data = Data}) ->
    encode_record(Name, Type, Ttl, Data);
encode_record(#dns_rr{name = Name, type = Type = ?DNS_TYPE_WALLET, ttl = Ttl, data = Data}) ->
    encode_record(Name, Type, Ttl, Data);
encode_record(#dns_rr{name = Name, type = Type = ?DNS_TYPE_EUI48, ttl = Ttl, data = Data}) ->
    encode_record(Name, Type, Ttl, Data);
encode_record(#dns_rr{name = Name, type = Type = ?DNS_TYPE_EUI64, ttl = Ttl, data = Data}) ->
    encode_record(Name, Type, Ttl, Data);
encode_record(#dns_rr{name = Name, type = Type = ?DNS_TYPE_CSYNC, ttl = Ttl, data = Data}) ->
    encode_record(Name, Type, Ttl, Data);
encode_record(#dns_rr{name = Name, type = Type = ?DNS_TYPE_DSYNC, ttl = Ttl, data = Data}) ->
    encode_record(Name, Type, Ttl, Data);
encode_record(#dns_rr{name = Name, type = Type = ?DNS_TYPE_ZONEMD, ttl = Ttl, data = Data}) ->
    encode_record(Name, Type, Ttl, Data);
encode_record(Record) ->
    ?LOG_WARNING(#{what => unable_to_encode_record, record => Record}, ?LOG_METADATA),
    not_implemented.

encode_record(Name, Type, Ttl, Data) ->
    #{
        ~"name" => erlang:iolist_to_binary(io_lib:format("~s.", [Name])),
        ~"type" => dns_names:type_name(Type),
        ~"ttl" => Ttl,
        ~"content" => iolist_to_binary(dns_zone:encode_rdata(Data))
    }.

try_custom_encoders(_, []) ->
    [];
try_custom_encoders(Record, [Encoder | Rest]) ->
    case Encoder(Record) of
        not_implemented ->
            try_custom_encoders(Record, Rest);
        EncodedData ->
            [EncodedData]
    end.
