%% Copyright (c) 2014, SiftLogic LLC
%%
%% Permission to use, copy, modify, and/or distribute this software for any
%% purpose with or without fee is hereby granted, provided that the above
%% copyright notice and this permission notice appear in all copies.
%%
%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
%% WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
%% MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
%% ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
%% WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
%% ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
%% OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

-module(erldns_SUITE).
%% API
-export([all/0,
         init_per_suite/1,
         end_per_suite/1,
         init_per_testcase/2]).

-export([mnesia_API_test/1,
         json_API_test/1,
         server_children_test/1,
         test_zone_modify/1,
         increment_soa/1,
         query_tests/1]).

-include("../include/erldns.hrl").
-include("../deps/dns/include/dns.hrl").
all() ->
    [mnesia_API_test, json_API_test, server_children_test, test_zone_modify, increment_soa, query_tests].

init_per_suite(Config) ->
    application:start(erldns_app),
    Config.

end_per_suite(Config) ->
    application:stop(erldns_app),
    Config.

init_per_testcase(mnesia_API_test, Config) ->
    application:set_env(erldns, storage, [{type, erldns_storage_mnesia}, {dir, "test_db3"}]),
    ok = erldns_storage:create(schema),
    ok = erldns_storage:create(zones),
    Config;
init_per_testcase(json_API_test, Config) ->
    application:set_env(erldns, storage, [{type, erldns_storage_json}]),
    Config;
init_per_testcase(server_children_test, Config) ->
    Config;
init_per_testcase(test_zone_modify, Config) ->
    application:set_env(erldns, storage, [{type, erldns_storage_mnesia}, {dir, "test_db4"}]),
    ok =  erldns_storage:create(schema),
    ok = erldns_storage:create(zones),
    Config;
init_per_testcase(increment_soa, Config) ->
    Config;
init_per_testcase(query_tests, Config) ->
    Config.

mnesia_API_test(_Config) ->
    erldns_storage_mnesia = erldns_config:storage_type(),
    DNSRR = #dns_rr{name = <<"TEST DNSRR NAME">>, class = 1, type = 0, ttl = 0, data = <<"TEST DNSRR DATA">>},
    ZONE1 = #zone{name = <<"TEST NAME 1">>, version = <<"1">>,authority =  [], record_count = 0, records = [], records_by_name = DNSRR, records_by_type = DNSRR},
    ZONE2 = #zone{name = <<"TEST NAME 2">>, version = <<"1">>,authority =  [], record_count = 0, records = [], records_by_name = DNSRR, records_by_type = DNSRR},
    ZONE3 = #zone{name = <<"TEST NAME 3">>, version = <<"1">>,authority =  [], record_count = 0, records = [], records_by_name = DNSRR, records_by_type = DNSRR},
    ZONE4 = #zone{name = <<"TEST NAME 4">>, version = <<"1">>,authority =  [], record_count = 0, records = [], records_by_name = DNSRR, records_by_type = DNSRR},
    ZONE5 = #zone{name = <<"TEST NAME 5">>, version = <<"1">>,authority =  [], record_count = 0, records = [], records_by_name = DNSRR, records_by_type = DNSRR},
    mnesia:wait_for_tables([zones], 10000),
    ok = erldns_storage:insert(zones, ZONE1),
    ok = erldns_storage:insert(zones, ZONE2),
    ok = erldns_storage:insert(zones, ZONE3),
    ok = erldns_storage:insert(zones, {<<"Test Name">>, ZONE4}),
    ok = erldns_storage:insert(zones, {<<"Test Name">>, ZONE5}),
    %%Iterate through table and see all the entrys.
    Iterator =  fun(Rec,_)->
                        io:format("~p~n",[Rec]),
                        []
                end,
    erldns_storage:foldl(Iterator, [], zones),
    erldns_storage:select(zones, <<"TEST NAME 1">>),
    ok = erldns_storage:delete(zones, <<"TEST NAME 1">>),
    ok = erldns_storage:empty_table(zones),
    ok = erldns_storage:delete_table(zones),
    %%authority test
    ok = erldns_storage:create(authorities),
    mnesia:wait_for_tables([authorities], 10000),
    AUTH1 = #authorities{owner_name = <<"Test Name">>, ttl = 1, class = <<"test calss">>, name_server = <<"Test Name Server">>,
                         email_addr = <<"test email">>, serial_num = 1, refresh = 1, retry = 1, expiry = 1, nxdomain = <<"test domain">>},
    AUTH2 = #authorities{owner_name = <<"Test Name">>, ttl = 1, class = <<"test calss">>, name_server = <<"Test Name Server">>,
                         email_addr = <<"test email">>, serial_num = 1, refresh = 1, retry = 1, expiry = 1, nxdomain = <<"test domain">>},
    AUTH3 = #authorities{owner_name = <<"Test Name">>, ttl = 1, class = <<"test calss">>, name_server = <<"Test Name Server">>,
                         email_addr = <<"test email">>, serial_num = 1, refresh = 1, retry = 1, expiry = 1, nxdomain = <<"test domain">>},
    ok = erldns_storage:insert(authorities, AUTH1),
    ok = erldns_storage:insert(authorities, AUTH2),
    ok = erldns_storage:insert(authorities, AUTH3),
    erldns_storage:foldl(Iterator, [], authorities),
    erldns_storage:select(authorities, <<"Test Name">>),
    ok = erldns_storage:delete(authorities, AUTH1),
    ok = erldns_storage:empty_table(authorities),
    ok = erldns_storage:delete_table(authorities),
    io:format("Test completed for mnesia API~n").

json_API_test(_Config) ->
    erldns_storage_json = erldns_config:storage_type(),
    DNSRR = #dns_rr{name = <<"TEST DNSRR NAME">>, class = 1, type = 0, ttl = 0, data = <<"TEST DNSRR DATA">>},
    ZONE1 = #zone{name = <<"TEST NAME 1">>, version = <<"1">>,authority =  [], record_count = 0, records = [], records_by_name = DNSRR, records_by_type = DNSRR},
    ZONE2 = #zone{name = <<"TEST NAME 2">>, version = <<"1">>,authority =  [], record_count = 0, records = [], records_by_name = DNSRR, records_by_type = DNSRR},
    ZONE3 = #zone{name = <<"TEST NAME 3">>, version = <<"1">>,authority =  [], record_count = 0, records = [], records_by_name = DNSRR, records_by_type = DNSRR},
    ZONE4 = #zone{name = <<"TEST NAME 4">>, version = <<"1">>,authority =  [], record_count = 0, records = [], records_by_name = DNSRR, records_by_type = DNSRR},
    ZONE5 = #zone{name = <<"TEST NAME 5">>, version = <<"1">>,authority =  [], record_count = 0, records = [], records_by_name = DNSRR, records_by_type = DNSRR},
    ok = erldns_storage:create(zones),
    ok = erldns_storage:insert(zones, ZONE1),
    ok = erldns_storage:insert(zones, ZONE2),
    ok = erldns_storage:insert(zones, ZONE3),
    ok = erldns_storage:insert(zones, ZONE4),
    ok = erldns_storage:insert(zones, ZONE5),
    %%Iterate through table and see all the entrys.
    Iterator =  fun(Rec,_)->
                        io:format("~p~n",[Rec]),
                        []
                end,
    erldns_storage:foldl(Iterator, [], zones),
    erldns_storage:select(zones, <<"TEST NAME 1">>),
    ok = erldns_storage:delete(zones, <<"TEST NAME 1">>),
    ok = erldns_storage:empty_table(zones),
    ok = erldns_storage:delete_table(zones),
    io:format("Test completed for json API~n").

server_children_test(_Config) ->
    {ok, IFAddrs} = inet:getifaddrs(),
    Config = lists:foldl(fun(IFList, Acc) ->
                                 {_, List} = IFList,
                                 [List | Acc]
                         end, [], IFAddrs),
    AddressesWithPorts = lists:foldl(fun(Conf, Acc) ->
                                             {addr, Addr} = lists:keyfind(addr, 1, Conf),
                                             [{Addr, 8053} | Acc]
                                     end, [], Config),
    Addresses = lists:foldr(fun({Addr, _Port} = _Element, Acc) ->
                                    [Addr| Acc]
                            end, [], AddressesWithPorts),
    io:format("AddressPort: ~p~n", [AddressesWithPorts]),
    io:format("Address: ~p~n", [Addresses]),
    ok = application:set_env(erldns, servers, [
                                               [{port, 8053},
                                                {listen, Addresses},
                                                {protocol, [tcp, udp]},
                                                {worker_pool, [
                                                               {size, 10}, {max_overflow, 20}
                                                              ]}]
                                              ]),
    ok = application:set_env(erldns, storage, [{type, erldns_storage_mnesia}, {dir, "db"}]),
    erldns_storage_mnesia = erldns_config:storage_type(),
    ok = erldns:start(),
    io:format("Loaded and started servers successfully~n"),
    timer:sleep(1000),
    {ok, _} = inet_res:nnslookup("example.com", any, a, AddressesWithPorts, 10000),
    io:format("Test completed for server_children~n").

test_zone_modify(_Config) ->
    erldns_storage_mnesia = erldns_config:storage_type(),
    ok = erldns_storage:create(schema),
    ok = erldns_storage:create(zones),
    {ok, _} = erldns_storage:load_zones("/opt/erl-dns/priv/example.zone.json"),
    ok = erldns_zone_cache:add_record(<<"example.com">>,
                                      {dns_rr,<<"example.com">>,1,1,3600,{dns_rrdata_a,{7,7,7,7}}}, false),
    ok = erldns_zone_cache:update_record(<<"example.com">>,
                                         {dns_rr,<<"example.com">>,1,1,3600,{dns_rrdata_a,{7,7,7,7}}},
                                         {dns_rr,<<"example.com">>,1,1,3600,{dns_rrdata_a,{77,77,77,77}}}, false),
    ok = erldns_zone_cache:delete_record(<<"example.com">>,
                                         {dns_rr,<<"example.com">>,1,1,3600,{dns_rrdata_a,{77,77,77,77}}}, false).

increment_soa(_Config) ->
    {ok, #zone{authority = [#dns_rr{data = #dns_rrdata_soa{serial = OldSerial}}]} = OldZone}
        = erldns_zone_cache:get_zone_with_records(<<"example.com">>),
    erldns_zone_cache:increment_soa(<<"example.com">>),
    {ok, #zone{authority = [#dns_rr{data = #dns_rrdata_soa{serial = NewSerial}}]} = NewZone}
        = erldns_zone_cache:get_zone_with_records(<<"example.com">>),
    case NewSerial =:= (OldSerial + 1) of
        true -> ok;
        false -> ct:fail(soa_didnt_increment)
    end.

query_tests(_Config) ->
    io:format("ERLDNS Should already be started from previous test~n"),
    ok  = application:ensure_started(erldns),
    timer:sleep(1000),
    io:format("You have to have the examples.zone.json file for this to work~n"),
    {ok, _} = erldns_storage:load_zones("/opt/erl-dns/priv/example.zone.json"),
    {ok, IFAddrs} = inet:getifaddrs(),
    Config = lists:foldl(fun(IFList, Acc) ->
                                 {_, List} = IFList,
                                 [List | Acc]
                         end, [], IFAddrs),
    AddressesWithPorts = lists:foldl(fun(Conf, Acc) ->
                                             {addr, Addr} = lists:keyfind(addr, 1, Conf),
                                             [{Addr, 8053} | Acc]
                                     end, [], Config),
    io:format("**************Starting Query Test**************"),
    {ok, A} = inet_res:nnslookup("example.com", any, a, AddressesWithPorts, 10000),
    {ok, B} = inet_res:nnslookup("example.com", any, aaaa, AddressesWithPorts, 10000),
    {ok, C} = inet_res:nnslookup("example.com", any, srv, AddressesWithPorts, 10000),
    {ok, D} = inet_res:nnslookup("example.com", any, cname, AddressesWithPorts, 10000),
    {ok, E} = inet_res:nnslookup("example.com", any, ns, AddressesWithPorts, 10000),
    {ok, F} = inet_res:nnslookup("example.com", any, mx, AddressesWithPorts, 10000),
    {ok, G} = inet_res:nnslookup("example.com", any, spf, AddressesWithPorts, 10000),
    {ok, H} = inet_res:nnslookup("example.com", any, txt, AddressesWithPorts, 10000),
    {ok, I} = inet_res:nnslookup("example.com", any, soa, AddressesWithPorts, 10000),
    {ok, J} = inet_res:nnslookup("example.com", any, naptr, AddressesWithPorts, 10000),
    {ok, K} = inet_res:nnslookup("example.com", any, axfr, AddressesWithPorts, 10000),
    io:format("Results: ~n"
              "A: ~p~n"
              "AAAA: ~p~n"
              "SRV: ~p~n"
              "CNAME: ~p~n"
              "NS: ~p~n"
              "MX: ~p~n"
              "SPF: ~p~n"
              "TXT: ~p~n"
              "SOA: ~p~n"
              "NAPTR: ~p~n"
              "AFXR: ~p~n",
              [A, B, C, D, E, F, G, H, I, J, K]).
