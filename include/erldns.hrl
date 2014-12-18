%% Erlang 17 moves various types into module namespaces
%% Use the ifdef to be backward compatible
-ifdef(namespaced_types).
-type edns_set() :: sets:set().
-type edns_dict() :: dict:dict().
-type edns_gb_tree() :: gb_trees:gb_tree().
-else.
-type edns_set() :: set().
-type edns_dict() :: dict().
-type edns_gb_tree() :: gb_tree().
-endif.

-record(partial_zone, {
          name :: dns:dname(),
          allow_notify = [] :: [inet:ip_address()],
          allow_transfer = [] :: [inet:ip_address()],
          allow_update = [] :: [inet:ip_address()],
          also_notify = [] :: [inet:ip_address()],
          notify_source = {127,0,0,1} :: inet:ip_address(),
          records = [] :: [dns:rr()],
          sha = <<>> :: binary()
         }).

-record(zone, {
          name :: dns:dname(),
          allow_notify :: [inet:ip_address()],
          allow_transfer :: [inet:ip_address()],
          allow_update :: [inet:ip_address()],
          also_notify :: [inet:ip_address()],
          notify_source :: inet:ip_address(),
          version :: binary(),
          authority = [] :: [dns:rr()],
          record_count = 0 :: non_neg_integer(),
          records = [] :: [dns:rr()],
          records_by_name :: [dns:rr()],
          records_by_type :: [dns:rr()]
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

-define(ADMIN_PORT, 9000).
-define(DNS_LISTEN_PORT, 8053).
-define(LOCAL_HOSTS, [{127, 0, 0, 1}, {0, 0, 0, 0, 0, 0, 0, 1}]).