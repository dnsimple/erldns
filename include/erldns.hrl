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

-record(zone, {
    name :: dns:dname(),
    version :: binary(),
    authority = [] :: [dns:rr()],
    record_count = 0 :: non_neg_integer(),
    records = [] :: [dns:rr()],
    records_by_name :: [dns:rr()],
    records_by_type :: [dns:rr()]
  }).
