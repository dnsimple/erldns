-module(erldns_zone_encoder).
-moduledoc """
A process that maintains a collection of encoders in its state
for encoding zones from their Erlang representation to JSON.
""".

-behaviour(gen_server).

-include_lib("dns_erlang/include/dns.hrl").
-include_lib("kernel/include/logger.hrl").

-include("erldns.hrl").

-export([
    zone_meta_to_json/1,
    zone_to_json/1,
    zone_records_to_json/2,
    zone_records_to_json/3,
    register_encoders/1,
    register_encoder/1,
    list_encoders/0
]).

-export([start_link/0, init/1, handle_call/3, handle_cast/2, terminate/2]).

-record(state, {encoders :: [encoder()]}).
-type state() :: #state{}.

-type encoder() :: fun((dns:rr()) -> not_implemented | json:encode_value()).
-callback encode_record(dns:rr()) -> not_implemented | json:encode_value().

% Public API

-doc "Encode a Zone meta data into JSON.".
-spec zone_meta_to_json(erldns:zone()) -> binary().
zone_meta_to_json(Zone) ->
    json_encode_kw_list([
        {~"erldns", [
            {~"zone", [
                {~"name", Zone#zone.name},
                {~"version", Zone#zone.version},
                % Note: Private key material is purposely omitted
                {~"records_count", length(erldns_zone_cache:get_zone_records(Zone#zone.name))}
            ]}
        ]}
    ]).

-doc "Encode a Zone meta data plus all of its records into JSON.".
-spec zone_to_json(erldns:zone()) -> binary().
zone_to_json(Zone) ->
    Encoders = list_encoders(),
    encode_zone_to_json(Zone, Encoders).

-doc "Encode the records in the zone with the given RRSet name and type into JSON".
-spec zone_records_to_json(dns:dname(), dns:dname()) -> binary().
zone_records_to_json(ZoneName, RecordName) ->
    Encoders = list_encoders(),
    encode_zone_records_to_json(ZoneName, RecordName, Encoders).

-doc "Encode the records in the zone with the given RRSet name and type into JSON".
-spec zone_records_to_json(dns:dname(), dns:dname(), binary()) -> binary().
zone_records_to_json(ZoneName, RecordName, RecordType) ->
    Encoders = list_encoders(),
    encode_zone_records_to_json(ZoneName, RecordName, RecordType, Encoders).

-doc "Register a single encoder module.".
-spec register_encoder(module()) -> ok.
register_encoder(Module) ->
    register_encoders([Module]).

-doc "Register a list of encoder modules.".
-spec register_encoders([module()]) -> ok.
register_encoders(Modules) ->
    ?LOG_NOTICE(#{what => registering_custom_encoders, encoders => Modules}),
    gen_server:call(?MODULE, {register_encoders, Modules}).

-doc "Get the list of registered zone parsers.".
-spec list_encoders() -> [encoder()].
list_encoders() ->
    persistent_term:get(?MODULE, []).

% Gen server hooks

% Internal API

encode_zone_to_json(Zone, Encoders) ->
    Records = records_to_json(Zone, Encoders),
    FilteredRecords = lists:filter(record_filter(), Records),
    json_encode_kw_list([
        {~"erldns", [
            {~"zone", [
                {~"name", Zone#zone.name},
                {~"version", Zone#zone.version},
                {~"records_count", length(FilteredRecords)},
                % Note: Private key material is purposely omitted
                {~"records", FilteredRecords}
            ]}
        ]}
    ]).

encode_zone_records_to_json(_ZoneName, RecordName, Encoders) ->
    Records = erldns_zone_cache:get_records_by_name(RecordName),
    json_encode_kw_list(lists:filter(record_filter(), lists:map(encode(Encoders), Records))).

encode_zone_records_to_json(_ZoneName, RecordName, RecordType, Encoders) ->
    Records = erldns_zone_cache:get_records_by_name_and_type(
        RecordName, erldns_records:name_type(RecordType)
    ),
    json_encode_kw_list(lists:filter(record_filter(), lists:map(encode(Encoders), Records))).

record_filter() ->
    fun(R) ->
        case R of
            [] -> false;
            {} -> false;
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

json_encode_kw_list(KwList) when is_list(KwList) ->
    iolist_to_binary(json:encode(KwList, fun json_encode_term/2)).

json_encode_term([{_, _} | _] = Value, Encode) -> json:encode_key_value_list(Value, Encode);
json_encode_term(Other, Encode) -> json:encode_value(Other, Encode).

-doc false.
-spec start_link() -> gen_server:start_ret().
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, noargs, []).

-doc false.
-spec init(noargs) -> {ok, state()}.
init(noargs) ->
    process_flag(trap_exit, true),
    CustomEncoders = application:get_env(erldns, custom_zone_encoders, []),
    Encoders = [fun Module:encode_record/1 || Module <- CustomEncoders],
    persistent_term:put(?MODULE, Encoders),
    {ok, #state{encoders = Encoders}}.

-doc false.
-spec handle_call(dynamic(), gen_server:from(), state()) ->
    {reply, dynamic(), state()}.
handle_call({register_encoders, Modules}, _From, State) ->
    Encoders = [fun Module:encode_record/1 || Module <- Modules],
    NewEncoders = State#state.encoders ++ Encoders,
    persistent_term:put(?MODULE, NewEncoders),
    {reply, ok, State#state{encoders = NewEncoders}};
handle_call(Call, From, State) ->
    ?LOG_INFO(#{what => unexpected_call, from => From, call => Call}),
    {reply, not_implemented, State}.

-doc false.
-spec handle_cast(dynamic(), state()) -> {noreply, state()}.
handle_cast(Cast, State) ->
    ?LOG_INFO(#{what => unexpected_cast, cast => Cast}),
    {noreply, State}.

-spec terminate(term(), state()) -> any().
terminate(_, _) ->
    persistent_term:erase(?MODULE).
