-record(zone, {
    name :: dns:dname(),
    version :: binary(),
    authority = [] :: [dns:rr()],
    record_count = 0 :: non_neg_integer(),
    records = [] :: [dns:rr()],
    records_by_name :: [dns:rr()],
    records_by_type :: [dns:rr()],
    key_signing_key :: crypto:rsa_private(),
    zone_signing_key :: crypto:rsa_private()
  }).

-define(DNSKEY_ZSK_TYPE, 256).
-define(DNSKEY_KSK_TYPE, 257).
