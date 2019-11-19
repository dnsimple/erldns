-include_lib("dns_erlang/include/dns_records.hrl").

-record(keyset, {
    key_signing_key :: crypto:rsa_private(),
    key_signing_key_tag :: non_neg_integer(),
    key_signing_alg :: non_neg_integer(),
    zone_signing_key :: crypto:rsa_private(),
    zone_signing_key_tag :: non_neg_integer(),
    zone_signing_alg :: non_neg_integer(),
    inception :: erlang:timestamp() | calendar:datetime1970(),
    valid_until :: erlang:timestamp() | calendar:datetime1970()
  }).

-record(zone, {
    name :: dns:dname(),
    version :: binary(),
    authority = [] :: [dns:rr()],
    record_count = 0 :: non_neg_integer(),
    records = [] :: [dns:rr()] | trimmed,
    records_by_name ::  #{binary() => [dns:rr()]} | trimmed,
    %% records_by_type is no longer in use, but cannot (easily) be deleted due to Mnesia schema evolution
    %% We cannot set it to undefined, because, again, when fetched from Mnesia, it may be set
    records_by_type :: term(),
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

-define(DNSKEY_ZSK_TYPE, 256).
-define(DNSKEY_KSK_TYPE, 257).
