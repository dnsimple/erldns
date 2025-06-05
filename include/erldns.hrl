-include_lib("dns_erlang/include/dns_records.hrl").

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
    keysets :: [erldns:keyset()]
}).
-record(authorities, {
    owner_name,
    ttl,
    class,
    name_server,
    email_addr,
    serial_num,
    refresh,
    retry,
    expiry,
    nxdomain
}).
-record(zone_records, {
    zone_name,
    fqdn,
    records
}).
-record(zone_records_typed, {
    zone_name,
    fqdn,
    type,
    records
}).
-record(sync_counters, {
    counter :: integer()
}).

-define(DNSKEY_ZSK_TYPE, 256).
-define(DNSKEY_KSK_TYPE, 257).
