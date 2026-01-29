-module(records_SUITE).
-compile([export_all, nowarn_export_all]).

-behaviour(ct_suite).

-include_lib("stdlib/include/assert.hrl").
-include_lib("dns_erlang/include/dns.hrl").

-spec all() -> [ct_suite:ct_test_def()].
all() ->
    [{group, all}].

-spec groups() -> [ct_suite:ct_group_def()].
groups() ->
    [
        {all, [parallel], [
            wildcard_qname,
            minimum_soa_ttl,
            replace_name,
            match_name,
            match_type,
            match_types,
            match_wildcard,
            match_delegation,
            match_wildcard_label
        ]}
    ].

%% Tests
wildcard_qname(_) ->
    ?assertEqual(<<"*.b.example.com">>, erldns_records:wildcard_qname(<<"a.b.example.com">>)).

minimum_soa_ttl(_) ->
    ?assertMatch(
        #dns_rr{ttl = 3600},
        erldns_records:minimum_soa_ttl(#dns_rr{ttl = 3600}, #dns_rrdata_a{})
    ),
    ?assertMatch(
        #dns_rr{ttl = 30},
        erldns_records:minimum_soa_ttl(#dns_rr{ttl = 3600}, #dns_rrdata_soa{minimum = 30})
    ),
    ?assertMatch(
        #dns_rr{ttl = 30},
        erldns_records:minimum_soa_ttl(#dns_rr{ttl = 30}, #dns_rrdata_soa{minimum = 3600})
    ).

replace_name(_) ->
    ?assertEqual([], lists:map(erldns_records:replace_name(<<"example">>), [])),
    ?assertMatch(
        [#dns_rr{name = <<"example">>}],
        lists:map(erldns_records:replace_name(<<"example">>), [#dns_rr{name = <<"test.com">>}])
    ).

match_name(_) ->
    ?assert(
        lists:any(erldns_records:match_name(<<"example.com">>), [
            #dns_rr{name = <<"example.com">>}
        ])
    ),
    ?assertNot(
        lists:any(erldns_records:match_name(<<"example.com">>), [
            #dns_rr{name = <<"example.net">>}
        ])
    ).

match_type(_) ->
    ?assert(lists:any(erldns_records:match_type(?DNS_TYPE_A), [#dns_rr{type = ?DNS_TYPE_A}])),
    ?assertNot(
        lists:any(erldns_records:match_type(?DNS_TYPE_CNAME), [#dns_rr{type = ?DNS_TYPE_A}])
    ).

match_types(_) ->
    ?assert(
        lists:any(erldns_records:match_types([?DNS_TYPE_A]), [#dns_rr{type = ?DNS_TYPE_A}])
    ),
    ?assert(
        lists:any(erldns_records:match_types([?DNS_TYPE_A, ?DNS_TYPE_CNAME]), [
            #dns_rr{type = ?DNS_TYPE_A}
        ])
    ),
    ?assertNot(
        lists:any(erldns_records:match_types([?DNS_TYPE_CNAME]), [#dns_rr{type = ?DNS_TYPE_A}])
    ).

match_wildcard(_) ->
    ?assert(lists:any(erldns_records:match_wildcard(), [#dns_rr{name = <<"*.example.com">>}])),
    ?assertNot(
        lists:any(erldns_records:match_wildcard(), [#dns_rr{name = <<"www.example.com">>}])
    ).

match_delegation(_) ->
    ?assert(
        lists:any(erldns_records:match_delegation(<<"ns1.example.com">>), [
            #dns_rr{data = #dns_rrdata_ns{dname = <<"ns1.example.com">>}}
        ])
    ),
    ?assertNot(
        lists:any(erldns_records:match_delegation(<<"ns1.example.com">>), [
            #dns_rr{data = #dns_rrdata_ns{dname = <<"ns2.example.com">>}}
        ])
    ).

match_wildcard_label(_) ->
    ?assert(
        lists:any(
            erldns_records:match_wildcard_label(), dns_domain:split(<<"*.example.com">>)
        )
    ),
    ?assertNot(
        lists:any(
            erldns_records:match_wildcard_label(), dns_domain:split(<<"www.example.com">>)
        )
    ).
