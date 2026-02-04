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
-spec json_record_to_erlang(dynamic()) -> not_implemented | dns:rr() | badarg.
json_record_to_erlang(#{~"name" := _, ~"type" := _, ~"ttl" := _, ~"data" := Data} = JsonRecord) when
    Data =/= null
->
    try
        RR = #dns_rr{} = dns_json:from_map(JsonRecord),
        case RR#dns_rr.type of
            ?DNS_TYPE_DNSKEY -> dnssec:add_keytag_to_dnskey(RR);
            ?DNS_TYPE_CDNSKEY -> dnssec:add_keytag_to_cdnskey(RR);
            _ -> RR
        end
    catch
        error:{invalid_ipv4_in_json, _, _} = Reason:Stacktrace ->
            erlang:raise(error, Reason, Stacktrace);
        error:{invalid_ipv6_in_json, _, _} = Reason:Stacktrace ->
            erlang:raise(error, Reason, Stacktrace);
        error:{svcb_mandatory_validation_error, _} = Reason:Stacktrace ->
            erlang:raise(error, Reason, Stacktrace);
        Class:Reason:Stacktrace ->
            ?LOG_DEBUG(
                #{
                    what => from_map_failed,
                    class => Class,
                    reason => Reason,
                    stacktrace => Stacktrace,
                    record => JsonRecord
                },
                ?LOG_METADATA
            ),
            not_implemented
    end;
json_record_to_erlang(#{}) ->
    not_implemented.
