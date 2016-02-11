-module(print_delegate).
-behaviour(erldns_resolver).
-export([get_records_by_name/1]).
get_records_by_name(Qname) ->
    io:format("get_records_by_name(~p).~n", [Qname]),
    [].
