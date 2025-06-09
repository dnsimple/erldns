-module(resolver_SUITE).
-compile([export_all, nowarn_export_all]).

-behaviour(ct_suite).

-include_lib("stdlib/include/assert.hrl").
-include_lib("dns_erlang/include/dns.hrl").
-include_lib("erldns/include/erldns.hrl").

-spec all() -> [ct_suite:ct_test_def()].
all() ->
    [
        resolve_no_question_returns_message,
        resolve_rrsig_refused,
        resolve_no_authority_refused,
        resolve_authoritative_host_not_found,
        resolve_authoritative_zone_cut,
        resolve_authoritative_zone_cut_with_cnames
    ].

-spec groups() -> [ct_suite:ct_group_def()].
groups() ->
    [].

-spec init_per_suite(ct_suite:ct_config()) -> ct_suite:ct_config().
init_per_suite(Config) ->
    Config.

-spec end_per_suite(ct_suite:ct_config()) -> term().
end_per_suite(Config) ->
    Config.

-spec init_per_group(ct_suite:ct_groupname(), ct_suite:ct_config()) -> ct_suite:ct_config().
init_per_group(_, Config) ->
    Config.

-spec end_per_group(ct_suite:ct_groupname(), ct_suite:ct_config()) -> term().
end_per_group(_, _Config) ->
    ok.

-spec init_per_testcase(ct_suite:ct_testcase(), ct_suite:ct_config()) -> ct_suite:ct_config().
init_per_testcase(_, Config) ->
    Config.

-spec end_per_testcase(ct_suite:ct_testcase(), ct_suite:ct_config()) -> term().
end_per_testcase(_, Config) ->
    Config.

%% Tests
resolve_no_question_returns_message(_) ->
    Q = #dns_message{questions = []},
    ?assertEqual(Q, erldns_resolver:resolve(Q, [], {1, 1, 1, 1})).

resolve_rrsig_refused(_) ->
    Q = #dns_message{questions = [#dns_query{type = ?DNS_TYPE_RRSIG}]},
    A = erldns_resolver:resolve(Q, [], {1, 1, 1, 1}),
    ?assertEqual(?DNS_RCODE_REFUSED, A#dns_message.rc).

resolve_no_authority_refused(_) ->
    Q = #dns_message{
        questions = [#dns_query{type = Qtype = ?DNS_TYPE_A, name = Qname = ~"example.com"}]
    },
    A = erldns_resolver:resolve_qname_and_qtype(Q, [], Qname, Qtype, {1, 1, 1, 1}),
    ?assertEqual(?DNS_RCODE_REFUSED, A#dns_message.rc).

resolve_authoritative_host_not_found(_) ->
    erldns_zone_cache:start_link(),
    Qname = ~"example.com",
    Z = #zone{
        name = ~"example.com",
        authority = Authority = [#dns_rr{name = ~"example.com", type = ?DNS_TYPE_SOA}]
    },
    Q = #dns_message{questions = [#dns_query{name = Qname, type = Qtype = ?DNS_TYPE_A}]},
    A = erldns_resolver:resolve_authoritative(Q, Qname, Qtype, Z, {}, _CnameChain = []),
    ?assertEqual(true, A#dns_message.aa),
    ?assertEqual(?DNS_RCODE_NXDOMAIN, A#dns_message.rc),
    ?assertEqual(Authority, A#dns_message.authority).

resolve_authoritative_zone_cut(_) ->
    erldns_zone_cache:start_link(),
    erldns_handler:start_link(),
    Qname = ~"delegated.example.com",
    NSRecord = [#dns_rr{name = Qname, type = ?DNS_TYPE_NS}],
    Z = #zone{
        name = ZoneName = ~"example.com",
        authority = Authority = [#dns_rr{name = ~"example.com", type = ?DNS_TYPE_SOA}]
    },
    Q = #dns_message{questions = [#dns_query{name = Qname, type = Qtype = ?DNS_TYPE_A}]},
    erldns_zone_cache:put_zone({ZoneName, ~"_", Authority ++ NSRecord}),
    A = erldns_resolver:resolve_authoritative(Q, Qname, Qtype, Z, {}, []),
    ?assertEqual(false, A#dns_message.aa),
    ?assertEqual(?DNS_RCODE_NOERROR, A#dns_message.rc),
    ?assertEqual(NSRecord, A#dns_message.authority),
    ?assertEqual([], A#dns_message.answers),
    erldns_zone_cache:delete_zone(ZoneName).

resolve_authoritative_zone_cut_with_cnames(_) ->
    erldns_zone_cache:start_link(),
    erldns_handler:start_link(),
    Qname = ~"delegated.example.com",
    CnameRecords =
        [
            #dns_rr{
                name = Qname,
                type = ?DNS_TYPE_CNAME,
                data = #dns_rrdata_cname{dname = ~"delegated-ns.example.com"}
            }
        ],
    NSRecord = [#dns_rr{name = ~"delegated-ns.example.com", type = ?DNS_TYPE_NS}],
    Z = #zone{
        name = ZoneName = ~"example.com",
        authority = Authority = [#dns_rr{name = ~"example.com", type = ?DNS_TYPE_SOA}]
    },
    Q = #dns_message{questions = [#dns_query{name = Qname, type = Qtype = ?DNS_TYPE_A}]},
    erldns_zone_cache:put_zone({ZoneName, ~"_", Authority ++ NSRecord ++ CnameRecords}),
    A = erldns_resolver:resolve_authoritative(Q, Qname, Qtype, Z, {}, _CnameChain = []),
    ?assertEqual(false, A#dns_message.aa),
    ?assertEqual(?DNS_RCODE_NOERROR, A#dns_message.rc),
    ?assertEqual(NSRecord, A#dns_message.authority),
    ?assertEqual(CnameRecords, A#dns_message.answers),
    erldns_zone_cache:delete_zone(ZoneName).
