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
    do_encode(Records, Encoders).

encode_zone_records_to_json(Zone, RecordName, Encoders) ->
    Records = erldns_zone_cache:get_records_by_name(Zone, RecordName),
    do_encode(Records, Encoders).

encode_zone_records_to_json(Zone, RecordName, RecordType, Encoders) ->
    Type = dns_names:name_type(RecordType),
    Records = erldns_zone_cache:get_records_by_name_and_type(Zone, RecordName, Type),
    do_encode(Records, Encoders).

records_to_json(Zone, Encoders) ->
    Records = erldns_zone_cache:get_zone_records(Zone),
    do_encode(Records, Encoders).

do_encode(Records, Encoders) ->
    lists:flatmap(fun(Record) -> encode_record(Record, Encoders) end, Records).

encode_record(
    #dns_rr{name = Name, type = Type, ttl = Ttl, data = Data} = Record,
    Encoders
) ->
    Encoded = erlang:iolist_to_binary(dns_zone:encode_rdata(Type, Data)),
    case Encoded of
        <<"\\#", _/binary>> ->
            %% dns_zone:encode_rdata/2 falls back to RFC 3597 \# length hex for unknown type
            ?LOG_WARNING(#{what => unable_to_encode_record, record => Record}, ?LOG_METADATA),
            try_custom_encoders(Record, Encoders);
        _ ->
            [
                #{
                    ~"name" => erlang:iolist_to_binary(io_lib:format("~s.", [Name])),
                    ~"type" => dns_names:type_name(Type),
                    ~"ttl" => Ttl,
                    ~"content" => Encoded
                }
            ]
    end.

try_custom_encoders(_, []) ->
    [];
try_custom_encoders(Record, [Encoder | Rest]) ->
    case Encoder(Record) of
        not_implemented ->
            try_custom_encoders(Record, Rest);
        EncodedData ->
            [EncodedData]
    end.
