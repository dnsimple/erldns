-ifndef('ERLDNS_H').
-define('ERLDNS_H', ok).

-record(keyset, {
    key_signing_key :: crypto:rsa_private(),
    key_signing_key_tag :: non_neg_integer(),
    key_signing_alg :: non_neg_integer(),
    zone_signing_key :: crypto:rsa_private(),
    zone_signing_key_tag :: non_neg_integer(),
    zone_signing_alg :: non_neg_integer(),
    inception :: integer(),
    valid_until :: integer()
}).

-record(zone, {
    %% We're assuming zones were stored with names already normalised,
    %% hence removing the need to re-normalize them on every fetch
    name :: dns:dname(),
    version :: binary(),
    authority = [] :: dns:authority(),
    record_count = 0 :: non_neg_integer(),
    records = [] :: [dns:rr()] | trimmed,
    keysets = [] :: [erldns:keyset()]
}).

-define(DNSKEY_ZSK_TYPE, 256).
-define(DNSKEY_KSK_TYPE, 257).

-endif.
