-ifndef('ERLDNS_H').
-define('ERLDNS_H', ok).

-record(keyset, {
    % key_signing_key and zone_signing_key are crypto:rsa_private() but this type is not exported
    key_signing_key :: dynamic(),
    key_signing_key_tag :: non_neg_integer(),
    key_signing_alg :: non_neg_integer(),
    zone_signing_key :: dynamic(),
    zone_signing_key_tag :: non_neg_integer(),
    zone_signing_alg :: non_neg_integer(),
    inception :: integer(),
    valid_until :: integer()
}).

-record(zone, {
    %% We're assuming zones were stored with names already normalised,
    %% hence removing the need to re-normalize them on every fetch
    labels :: dns:labels(),
    name :: dns:dname(),
    version :: erldns_zones:version(),
    authority = [] :: dns:authority(),
    record_count = 0 :: non_neg_integer(),
    records = [] :: [dns:rr()],
    keysets = [] :: [erldns:keyset()]
}).

-define(DNSKEY_ZSK_TYPE, 256).
-define(DNSKEY_KSK_TYPE, 257).

-endif.
