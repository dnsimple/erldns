-module(custom_zone_parser_test).

-include_lib("eunit/include/eunit.hrl").
-include_lib("dns_erlang/include/dns.hrl").

json_record_to_erlang_with_map_test() ->
    Record = sample_custom_zone_parser:json_record_to_erlang([<<"example.com">>, <<"SAMPLE">>, 60, #{<<"dname">> => <<"example.net">>}, undefined]),
    ?assertEqual(<<"example.com">>, Record#dns_rr.name),
    ?assertEqual(40000, Record#dns_rr.type),
    ?assertEqual(60, Record#dns_rr.ttl),
    ?assertEqual(<<"example.net">>, Record#dns_rr.data).

json_record_to_erlang_with_proplist_test() ->
    Record = sample_custom_zone_parser:json_record_to_erlang([<<"example.com">>, <<"SAMPLE">>, 60, [{<<"dname">>, <<"example.net">>}], undefined]),
    ?assertEqual(<<"example.com">>, Record#dns_rr.name),
    ?assertEqual(40000, Record#dns_rr.type),
    ?assertEqual(60, Record#dns_rr.ttl),
    ?assertEqual(<<"example.net">>, Record#dns_rr.data).
