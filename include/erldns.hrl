-include_lib("dns/include/dns_records.hrl").

-record(keyset, {
    key_signing_key :: crypto:rsa_private(),
    zone_signing_key :: crypto:rsa_private(),
    valid_until :: binary()
  }).

-record(zone, {
    name :: dns:dname(),
    version :: binary(),
    authority = [] :: [dns:rr()],
    record_count = 0 :: non_neg_integer(),
    records = [] :: [dns:rr()],
    records_by_name ::  dict:dict(binary(), [dns:rr()]) | trimmed,
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

-define(DNSKEY_ZSK_TYPE, 256).
-define(DNSKEY_KSK_TYPE, 257).
