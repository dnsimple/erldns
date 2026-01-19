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
encode_record(Record) ->
    ?LOG_WARNING(#{what => unable_to_encode_record, record => Record}, ?LOG_METADATA),
    not_implemented.

encode_record(Name, Type, Ttl, Data) ->
    #{
        ~"name" => erlang:iolist_to_binary(io_lib:format("~s.", [Name])),
        ~"type" => dns_names:type_name(Type),
        ~"ttl" => Ttl,
        ~"content" => encode_data(Data)
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

encode_data(#dns_rrdata_soa{
    mname = Mname,
    rname = Rname,
    serial = Serial,
    refresh = Refresh,
    retry = Retry,
    expire = Expire,
    minimum = Minimum
}) ->
    erlang:iolist_to_binary(
        io_lib:format("~s. ~s. (~w ~w ~w ~w ~w)", [
            Mname, Rname, Serial, Refresh, Retry, Expire, Minimum
        ])
    );
encode_data(#dns_rrdata_ns{dname = Dname}) ->
    erlang:iolist_to_binary(io_lib:format("~s.", [Dname]));
encode_data(#dns_rrdata_a{ip = Address}) ->
    list_to_binary(inet_parse:ntoa(Address));
encode_data(#dns_rrdata_aaaa{ip = Address}) ->
    list_to_binary(inet_parse:ntoa(Address));
encode_data(#dns_rrdata_caa{flags = Flags, tag = Tag, value = Value}) ->
    erlang:iolist_to_binary(io_lib:format("~w ~s \"~s\"", [Flags, Tag, Value]));
encode_data(#dns_rrdata_cname{dname = Dname}) ->
    erlang:iolist_to_binary(io_lib:format("~s.", [Dname]));
encode_data(#dns_rrdata_mx{preference = Preference, exchange = Dname}) ->
    erlang:iolist_to_binary(io_lib:format("~w ~s.", [Preference, Dname]));
encode_data(#dns_rrdata_hinfo{cpu = Cpu, os = Os}) ->
    erlang:iolist_to_binary(io_lib:format("~w ~w", [Cpu, Os]));
encode_data(#dns_rrdata_txt{txt = Text}) ->
    erlang:iolist_to_binary(io_lib:format("~s", [Text]));
encode_data(#dns_rrdata_sshfp{alg = Alg, fp_type = Fptype, fp = Fp}) ->
    erlang:iolist_to_binary(io_lib:format("~w ~w ~s", [Alg, Fptype, Fp]));
encode_data(#dns_rrdata_srv{priority = Priority, weight = Weight, port = Port, target = Dname}) ->
    erlang:iolist_to_binary(io_lib:format("~w ~w ~w ~s.", [Priority, Weight, Port, Dname]));
encode_data(#dns_rrdata_naptr{
    order = Order,
    preference = Preference,
    flags = Flags,
    services = Services,
    regexp = Regexp,
    replacement = Replacements
}) ->
    erlang:iolist_to_binary(
        io_lib:format("~w ~w ~s ~s ~s ~s", [
            Order, Preference, Flags, Services, Regexp, Replacements
        ])
    );
encode_data(#dns_rrdata_ds{
    keytag = KeyTag,
    alg = Alg,
    digest_type = DigestType,
    digest = Digest
}) ->
    escape_chars(
        io_lib:format("~w ~w ~w ~s", [KeyTag, Alg, DigestType, Digest])
    );
encode_data(#dns_rrdata_cds{
    keytag = KeyTag,
    alg = Alg,
    digest_type = DigestType,
    digest = Digest
}) ->
    escape_chars(
        io_lib:format("~w ~w ~w ~s", [KeyTag, Alg, DigestType, Digest])
    );
encode_data(#dns_rrdata_dnskey{
    flags = Flags, protocol = Protocol, alg = Alg, public_key = Key, keytag = KeyTag
}) ->
    escape_chars(
        io_lib:format("~w ~w ~w ~w ~w", [Flags, Protocol, Alg, Key, KeyTag])
    );
encode_data(#dns_rrdata_cdnskey{
    flags = Flags, protocol = Protocol, alg = Alg, public_key = Key, keytag = KeyTag
}) ->
    escape_chars(
        io_lib:format("~w ~w ~w ~w ~w", [Flags, Protocol, Alg, Key, KeyTag])
    );
encode_data(
    #dns_rrdata_rrsig{
        type_covered = TypeCovered,
        alg = Alg,
        labels = Labels,
        original_ttl = OriginalTtl,
        expiration = Expiration,
        inception = Inception,
        keytag = KeyTag,
        signers_name = SignersName,
        signature = Signature
    }
) ->
    escape_chars(
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
    );
encode_data(#dns_rrdata_tlsa{
    usage = Usage,
    selector = Selector,
    matching_type = MatchingType,
    certificate = Certificate
}) ->
    escape_chars(
        io_lib:format("~w ~w ~w ~s", [Usage, Selector, MatchingType, Certificate])
    );
encode_data(#dns_rrdata_svcb{
    svc_priority = Priority,
    target_name = TargetName,
    svc_params = SvcParams
}) ->
    ParamsStr = encode_svcb_params(SvcParams),
    case ParamsStr of
        [] ->
            erlang:iolist_to_binary(io_lib:format("~w ~s.", [Priority, TargetName]));
        _ ->
            erlang:iolist_to_binary(
                io_lib:format("~w ~s.~s", [Priority, TargetName, ParamsStr])
            )
    end;
encode_data(#dns_rrdata_https{
    svc_priority = Priority,
    target_name = TargetName,
    svc_params = SvcParams
}) ->
    ParamsStr = encode_svcb_params(SvcParams),
    case ParamsStr of
        [] ->
            erlang:iolist_to_binary(io_lib:format("~w ~s.", [Priority, TargetName]));
        _ ->
            erlang:iolist_to_binary(
                io_lib:format("~w ~s.~s", [Priority, TargetName, ParamsStr])
            )
    end;
encode_data(Data) ->
    ?LOG_INFO(#{what => unable_to_encode_rrdata, data => Data}, ?LOG_METADATA),
    not_implemented.

%% Helper function to encode SVCB service parameters
-spec encode_svcb_params(dns:svcb_svc_params()) -> iolist().
encode_svcb_params(SvcParams) when is_map(SvcParams) ->
    SortedParams = lists:sort(maps:to_list(SvcParams)),
    encode_svcb_params(SortedParams, []).

-spec encode_svcb_params([{dns:uint16(), term()}], [iolist()]) -> iolist().
encode_svcb_params([], Acc) ->
    lists:reverse(Acc);
encode_svcb_params([{Key, Value} | Rest], Acc) ->
    ParamStr =
        case {Key, Value} of
            {?DNS_SVCB_PARAM_MANDATORY, Keys} when is_list(Keys) ->
                KeyNames = [dns_names:svcb_param_name(K) || K <- Keys],
                io_lib:format(" mandatory=~s", [
                    string:join([binary_to_list(K) || K <- KeyNames], ",")
                ]);
            {?DNS_SVCB_PARAM_ALPN, Protocols} when is_list(Protocols) ->
                ProtocolStrs = [binary_to_list(P) || P <- Protocols],
                io_lib:format(" alpn=~s", [string:join(ProtocolStrs, ",")]);
            {?DNS_SVCB_PARAM_NO_DEFAULT_ALPN, none} ->
                " no-default-alpn";
            {?DNS_SVCB_PARAM_PORT, Port} when is_integer(Port) ->
                io_lib:format(" port=~w", [Port]);
            {?DNS_SVCB_PARAM_ECH, ECH} when is_binary(ECH) ->
                ECHBase64 = base64:encode(ECH),
                io_lib:format(" ech=~s", [ECHBase64]);
            {?DNS_SVCB_PARAM_IPV4HINT, IPs} when is_list(IPs) ->
                IPStrs = [inet_parse:ntoa(IP) || IP <- IPs],
                io_lib:format(" ipv4hint=~s", [string:join(IPStrs, ",")]);
            {?DNS_SVCB_PARAM_IPV6HINT, IPs} when is_list(IPs) ->
                IPStrs = [inet_parse:ntoa(IP) || IP <- IPs],
                io_lib:format(" ipv6hint=~s", [string:join(IPStrs, ",")]);
            {Key, Value} when is_binary(Value) ->
                %% Unknown parameter with binary value
                ValueBase64 = base64:encode(Value),
                io_lib:format(" key~w=~s", [Key, ValueBase64]);
            _ ->
                ""
        end,
    encode_svcb_params(Rest, [ParamStr | Acc]).

escape_chars(IoList) ->
    binary:encode_hex(erlang:iolist_to_binary(IoList)).
