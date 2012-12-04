-record(db_rr, {
    name,
    type,
    content,
    ttl,
    priority
  }).

-record(zone, {
    authority = [],
    records = [],
    records_by_name,
    records_by_type
  }).
