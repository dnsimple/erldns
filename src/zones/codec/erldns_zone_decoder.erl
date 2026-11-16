-module(erldns_zone_decoder).
-moduledoc false.

-include_lib("dns_erlang/include/dns.hrl").
-include_lib("kernel/include/logger.hrl").
-include_lib("erldns/include/erldns.hrl").
-include_lib("public_key/include/public_key.hrl").
-define(LOG_METADATA, #{domain => [erldns, zones, decoder]}).
-define(KEYSET_KEYS, [
    ~"ksk", ~"ksk_keytag", ~"ksk_alg", ~"zsk", ~"zsk_keytag", ~"zsk_alg", ~"inception", ~"until"
]).

-export([parse_keysets/1, finalize/1]).

-doc "Keep the decoded records, sorted and deduplicated, and log the others as unsupported.".
-spec finalize([erldns_zone_pipeline:entry()]) -> [dns:rr()].
finalize(Entries) ->
    Records = lists:filter(fun is_decoded/1, Entries),
    lists:usort(Records).

is_decoded(#dns_rr{}) ->
    true;
is_decoded(Entry) ->
    ?LOG_WARNING(#{what => unsupported_record, record => Entry}, ?LOG_METADATA),
    false.

-spec parse_keysets([json:decode_value()]) -> [erldns:keyset()].
parse_keysets(JsonKeys) when is_list(JsonKeys) ->
    parse_keysets(JsonKeys, []).

parse_keysets([], Keys) ->
    Keys;
parse_keysets([Key | Rest], Keys) ->
    KeySet = parse_keyset(Key),
    parse_keysets(Rest, [KeySet | Keys]).

% RFC4034: §3.1.5.  Signature Expiration and Inception Fields
%    The Signature Expiration and Inception field values specify a date
%    and time in the form of a 32-bit unsigned number of seconds elapsed
%    since 1 January 1970 00:00:00 UTC, ignoring leap seconds, in network
%    byte order.
parse_keyset(#{
    ~"ksk" := Ksk,
    ~"ksk_keytag" := KskTag,
    ~"ksk_alg" := KskAlg,
    ~"zsk" := Zsk,
    ~"zsk_keytag" := ZskTag,
    ~"zsk_alg" := ZskAlg,
    ~"inception" := Inception,
    ~"until" := Until
}) ->
    #keyset{
        key_signing_key = to_crypto_key(Ksk),
        key_signing_key_tag = KskTag,
        key_signing_alg = KskAlg,
        zone_signing_key = to_crypto_key(Zsk),
        zone_signing_key_tag = ZskTag,
        zone_signing_alg = ZskAlg,
        inception = calendar:rfc3339_to_system_time(binary_to_list(Inception), [{unit, second}]),
        valid_until = calendar:rfc3339_to_system_time(binary_to_list(Until), [{unit, second}])
    };
%% Raised without the keyset, so that its private keys stay out of the logs
parse_keyset(Key) when is_map(Key) ->
    Missing = ?KEYSET_KEYS -- maps:keys(Key),
    erlang:error({invalid_keyset, Missing});
parse_keyset(_) ->
    erlang:error(invalid_keyset).

to_crypto_key(KeyBin) ->
    DecodedKey = public_key:pem_entry_decode(lists:last(public_key:pem_decode(KeyBin))),
    extract_key(DecodedKey).

%% An RSA key with the numbers crypto signs by the CRT with, about twice as fast
%% as without them, each as its big-endian bytes, which crypto takes as they are
%% where it converts an integer on every signature
extract_key(#'RSAPrivateKey'{
    publicExponent = E,
    modulus = N,
    privateExponent = D,
    prime1 = P1,
    prime2 = P2,
    exponent1 = E1,
    exponent2 = E2,
    coefficient = C
}) ->
    [binary:encode_unsigned(Number) || Number <- [E, N, D, P1, P2, E1, E2, C]];
extract_key(#'ECPrivateKey'{privateKey = Key, parameters = {namedCurve, ?'secp256r1'}}) ->
    Key;
extract_key(#'ECPrivateKey'{privateKey = Key, parameters = {namedCurve, ?'secp384r1'}}) ->
    Key;
extract_key(#'ECPrivateKey'{privateKey = Key, parameters = {namedCurve, ?'id-Ed25519'}}) ->
    Key;
extract_key(#'ECPrivateKey'{privateKey = Key, parameters = {namedCurve, ?'id-Ed448'}}) ->
    Key.
