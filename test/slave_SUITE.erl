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

-module(slave_SUITE).
%% API
-export([all/0,
         init_per_suite/1,
         end_per_suite/1,
         init_per_testcase/2]).

-export([query_for_updated_records/1,
         query_for_axfr/1,
         zone_refresh_test/1,
         test_master_hidden/1,
         test_zone_add_delete_sync/1]).

-include("../include/erldns.hrl").
-include("../deps/dns/include/dns.hrl").
all() ->
    [query_for_updated_records, query_for_axfr, zone_refresh_test, test_master_hidden, test_zone_add_delete_sync].

init_per_suite(Config) ->
    ok = application:set_env(erldns, admin, [{listen, {127, 0, 0, 1}}, {port, 9000}]),
    ok = application:set_env(erldns, master_admin_server, {{10, 1, 10, 51}, 9000}),
    ok = application:set_env(erldns, storage, [{type, erldns_storage_mnesia}, {dir, "/opt/erl-dns/test/test_db2"}]),
    ok = application:set_env(erldns, servers, [
                                               [{port, 8053},
                                                {listen, [{127,0,0,1}]},
                                                {protocol, [tcp, udp]},
                                                {worker_pool, [
                                                               {size, 10}, {max_overflow, 20}
                                                              ]}]
                                              ]),
    ok = application:set_env(erldns, crypto, [{key, "29bba620-39dc-4426-bb59-43c284752ee1"}, {vector, "fd4c96ec-9c51-4e67-8ee8-e643b0f960d0"}]),
    ok = erldns:start(),
    ok = erldns_storage:create(schema),
    ok = erldns_storage:create(zones),
    {ok, _} = erldns_storage:load_zones("/opt/erl-dns/priv/example.zone.json"),
    Config.

end_per_suite(Config) ->
    application:stop(erldns_app),
    Config.

init_per_testcase(query_for_updated_records, Config) ->
    Config;
init_per_testcase(query_for_axfr, Config) ->
    Config;
init_per_testcase(zone_refresh_test, Config) ->
    Config;
init_per_testcase(test_master_hidden, Config) ->
    Config;
init_per_testcase(test_zone_add_delete_sync, Config) ->
    Config.

query_for_updated_records(_Config) ->
    io:format("NOTE: WILL FAIL IF MASTER IS 'HIDDEN'"),
    Records = erldns_zone_cache:get_records_by_name(<<"example.com">>),
    io:format("Old records: ~p~n", [Records]),
    {ok, Zone} = erldns_zone_cache:get_zone(<<"example.com">>),
    NewRecords = erldns_zone_transfer_worker:query_for_records(Zone#zone.notify_source, hd(erldns_config:get_address(inet)), Records),
    io:format("New records from master: ~p~n", [NewRecords]),
    %% If we got the same amount of records we queried for, the test passed.
    case length(NewRecords) =:= length(Records) of
        true ->
            ok;
        false ->
            ct:fail(didnt_get_all_records)
    end.

query_for_axfr(_Config) ->
    OldZone = erldns_zone_cache:get_zone_with_records(<<"example.com">>),
    try erldns_zone_transfer_worker:send_axfr(<<"example.com">>, {127,0,0,1}, {10,1,10,51}) of
        _ ->
            io:format("Hmm....should have caught an exit normal for send_afxr!"),
            ct:fail(didnt_catch_normal_exit)
    catch
        exit:normal -> io:format("Successful zone transfer!")
    end,
    NewZone = erldns_zone_cache:get_zone_with_records(<<"example.com">>),
    io:format("OldZone: ~p~n NewZone: ~p~n", [OldZone, NewZone]).

zone_refresh_test(_Config) ->
    ok  = application:ensure_started(erldns),
    {ok, Zone0} = erldns_zone_cache:get_zone_with_records(<<"example.com">>),
    %% We need to update our serial before getting an AXFR
    %% Update serial number
    Authority = hd(Zone0#zone.authority),
    SOA0 = Authority#dns_rr.data,
    OldSerial = 0,
    SOA = SOA0#dns_rrdata_soa{serial = OldSerial},
    Zone = erldns_zone_cache:build_zone(<<"example.com">>, Zone0#zone.allow_notify, Zone0#zone.allow_transfer,
                                        Zone0#zone.allow_update, Zone0#zone.also_notify, Zone0#zone.notify_source, Zone0#zone.version,
                                        [Authority#dns_rr{data = SOA}],  Zone0#zone.records),
    %% Put zone back into cache. And wait for it to expire
    ok = erldns_zone_cache:delete_zone(<<"example.com">>),
    ok = erldns_zone_cache:put_zone(<<"example.com">>, Zone),
    timer:sleep(15000),
    {ok, #zone{authority = [#dns_rr{data = Authority2}]}} = erldns_zone_cache:get_zone_with_records(<<"example.com">>),
    NewSerial = Authority2#dns_rrdata_soa.serial,
    case NewSerial =:= OldSerial of
        false ->
            ok;
        true ->
            ct:fail(zone_no_refresh)
    end.

test_master_hidden(_Config) ->
    io:format("Master must be configured as 'hidden'"),
    {ok, {dns_rec,
          {dns_header,_,_,_,_,_,_,_,_,_},
          _,
          [],   %%Answer (Should be empty)
          [],   %%NS List (Should be empty)
          []}} = inet_res:nnslookup("example.com", any, a, [{{10,1,10,51}, 8053}], 10000),
    {ok, {dns_rec,
          {dns_header,_,_,_,_,_,_,_,_,_},
          _,
          [],   %%Answer (Should be empty)
          [],   %%NS List (Should be empty)
          []}} = inet_res:nnslookup("example.com", any, aaaa, [{{10,1,10,51}, 8053}], 10000),
    {ok, {dns_rec,
          {dns_header,_,_,_,_,_,_,_,_,_},
          _,
          [],   %%Answer (Should be empty)
          [],   %%NS List (Should be empty)
          []}} = inet_res:nnslookup("example.com", any, srv, [{{10,1,10,51}, 8053}], 10000),
    {ok, {dns_rec,
          {dns_header,_,_,_,_,_,_,_,_,_},
          _,
          [],   %%Answer (Should be empty)
          [],   %%NS List (Should be empty)
          []}} = inet_res:nnslookup("example.com", any, cname, [{{10,1,10,51}, 8053}], 10000),
    {ok, {dns_rec,
          {dns_header,_,_,_,_,_,_,_,_,_},
          _,
          [],   %%Answer (Should be empty)
          [],   %%NS List (Should be empty)
          []}} = inet_res:nnslookup("example.com", any, ns, [{{10,1,10,51}, 8053}], 10000),
    {ok, {dns_rec,
          {dns_header,_,_,_,_,_,_,_,_,_},
          _,
          [],   %%Answer (Should be empty)
          [],   %%NS List (Should be empty)
          []}} = inet_res:nnslookup("example.com", any, mx, [{{10,1,10,51}, 8053}], 10000),
    {ok, {dns_rec,
          {dns_header,_,_,_,_,_,_,_,_,_},
          _,
          [],   %%Answer (Should be empty)
          [],   %%NS List (Should be empty)
          []}} = inet_res:nnslookup("example.com", any, spf, [{{10,1,10,51}, 8053}], 10000),
    {ok, {dns_rec,
          {dns_header,_,_,_,_,_,_,_,_,_},
          _,
          [],   %%Answer (Should be empty)
          [],   %%NS List (Should be empty)
          []}} = inet_res:nnslookup("example.com", any, txt, [{{10,1,10,51}, 8053}], 10000),
    {ok, {dns_rec,
          {dns_header,_,_,_,_,_,_,_,_,_},
          _,
          [],   %%Answer (Should be empty)
          [],   %%NS List (Should be empty)
          []}} = inet_res:nnslookup("example.com", any, soa, [{{10,1,10,51}, 8053}], 10000),
    {ok, {dns_rec,
          {dns_header,_,_,_,_,_,_,_,_,_},
          _,
          [],   %%Answer (Should be empty)
          [],   %%NS List (Should be empty)
          []}} = inet_res:nnslookup("example.com", any, naptr, [{{10,1,10,51}, 8053}], 10000),
    try erldns_zone_transfer_worker:send_axfr(<<"example.com">>, {127,0,0,1}, {10,1,10,51}) of
        _ ->
            io:format("Hmm....should have caught an exit normal for send_afxr!"),
            ct:fail(didnt_catch_normal_exit)
    catch
        exit:normal -> io:format("Successful zone transfer!")
    end.

test_zone_add_delete_sync(_Config) ->
    {MasterIP, Port} = erldns_config:get_master(),
    DNS = [
           #dns_rr{name = <<"test.com">>,class = 1,
                   type = 6,ttl = 3600,
                   data = #dns_rrdata_soa{mname = <<"ns1.test.com">>,
                                          rname = <<"admin.test.com">>,serial = 2013022001,
                                          refresh = 86400,retry = 7200,expire = 5,minimum = 300}},
        {dns_rr,<<"test.com">>,1,2,3600,
            {dns_rrdata_ns,<<"ns2.test.com">>}},
        {dns_rr,<<"ns2.test.com">>,1,1,3600,{dns_rrdata_a,{127,0,0,1}}}],
    Zone = erldns_zone_cache:build_zone(<<"test.com">>, [{127,0,0,1}, {10,1,10,51}], [{127,0,0,1}, {10,1,10,51}],
                                        [{10,1,10,51},{127,0,0,1}], [{10,1,10,51},{127,0,0,1}], {10,1,10,51}, 0, DNS),
    {ok, Socket1} = gen_tcp:connect(MasterIP, ?ADMIN_PORT, [binary, {active, false}, {ip, {127, 0, 0, 1}}]),
    Message1 = term_to_binary(Zone),
    ok = gen_tcp:send(Socket1, <<"test_add_zone_", Message1/binary>>),
    timer:sleep(2000),
    case erldns_zone_cache:get_zone_with_records(<<"test.com">>) of
        {ok, _TestZone1} ->
            ok;
        _ ->
            ct:fail(slave_did_not_sync)
    end,
    {ok, Socket2} = gen_tcp:connect(MasterIP, ?ADMIN_PORT, [binary, {active, false}, {ip, {127, 0, 0, 1}}]),
    ok = gen_tcp:send(Socket2, <<"test_delete_zone_", <<"test.com">>/binary>>),
    timer:sleep(2000),
    case erldns_zone_cache:get_zone_with_records(<<"test.com">>) of
        {ok, _TestZone2} ->
            ct:fail(slave_did_not_sync);
        _ ->
            ok
    end.
