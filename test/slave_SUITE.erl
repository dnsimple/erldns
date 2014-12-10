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

-export([query_tests/1]).

-include("../include/erldns.hrl").
-include("../deps/dns/include/dns.hrl").
all() ->
    [query_tests].

init_per_suite(Config) ->
    application:start(erldns_app),
    Config.

end_per_suite(Config) ->
    application:stop(erldns_app),
    Config.

init_per_testcase(query_tests, Config) ->
    Config.


query_tests(_Config) ->
    ok = erldns:start(),
    %% This test will initiate a query from master, we should have set the expire
    io:format("ERLDNS Should already be started from previous test~n"),
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
    {ok, _} = inet_res:nnslookup("example.com", any, a, AddressesWithPorts, 10000),
    {ok, _} = inet_res:nnslookup("example.com", any, aaaa, AddressesWithPorts, 10000),
    {ok, _} = inet_res:nnslookup("example.com", any, srv, AddressesWithPorts, 10000),
    {ok, _} = inet_res:nnslookup("example.com", any, cname, AddressesWithPorts, 10000),
    {ok, _} = inet_res:nnslookup("example.com", any, ns, AddressesWithPorts, 10000),
    {ok, _} = inet_res:nnslookup("example.com", any, mx, AddressesWithPorts, 10000),
    {ok, _} = inet_res:nnslookup("example.com", any, spf, AddressesWithPorts, 10000),
    {ok, _} = inet_res:nnslookup("example.com", any, txt, AddressesWithPorts, 10000),
    {ok, _} = inet_res:nnslookup("example.com", any, soa, AddressesWithPorts, 10000),
    {ok, _} = inet_res:nnslookup("example.com", any, naptr, AddressesWithPorts, 10000),
    {ok, _} = inet_res:nnslookup("example.com", any, axfr, AddressesWithPorts, 10000).
