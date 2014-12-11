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
         query_for_axfr/1]).

-include("../include/erldns.hrl").
-include("../deps/dns/include/dns.hrl").
all() ->
    [query_for_updated_records, query_for_axfr].

init_per_suite(Config) ->
    ok = application:set_env(erldns, servers, [
        [{port, 8053},
            {listen, [{127,0,0,1}]},
            {protocol, [tcp, udp]},
            {worker_pool, [
                {size, 10}, {max_overflow, 20}
            ]}]
    ]),
    ok = erldns:start(),
    Config.

end_per_suite(Config) ->
    application:stop(erldns_app),
    Config.

init_per_testcase(query_for_updated_records, Config) ->
    Config;
init_per_testcase(query_for_axfr, Config) ->
    Config.

query_for_updated_records(_Config) ->
    {ok, _} = erldns_storage:load_zones("/opt/erl-dns/priv/example.zone.json"),
    Records = erldns_zone_cache:get_records_by_name(<<"example.com">>),
    io:format("Old records: ~p~n", [Records]),
    {ok, Zone} = erldns_zone_cache:get_zone(<<"example.com">>),
    NewRecords = erldns_zone_transfer_worker:query_for_records(Zone#zone.notify_source, hd(erldns_config:get_address(inet)), Records),
    io:format("New records from master: ~p~n", [NewRecords]),
    %% If we got the same amount of records we wueried for, the test passed.
    true = length(NewRecords) =:= length(Records).

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
    io:format("OldZone: ~p~n NewZone: ~p~n", [OldZone, NewZone]),
    ok.
