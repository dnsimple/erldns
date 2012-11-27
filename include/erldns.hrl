-record(db_rr, {
    name,
    type,
    content,
    ttl,
    priority
  }).

-record(rr, {
    dns_rr,
    wildcard = false
  }).
