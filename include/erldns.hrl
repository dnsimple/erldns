-record(db_rr, {
    name,
    type,
    content,
    ttl,
    priority
  }).

-record(zone, {
    name,
    version,
    authority = [],
    record_count = 0,
    records = [],
    records_by_name,
    records_by_type
  }).
