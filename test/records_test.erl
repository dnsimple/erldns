-module(records_test).

-include_lib("dns_erlang/include/dns.hrl").
-include_lib("eunit/include/eunit.hrl").

wildcard_qname_test_() ->
    ?_assertEqual(<<"*.b.example.com">>, erldns_records:wildcard_qname(<<"a.b.example.com">>)).

minimum_soa_ttl_test_() ->
    [
        ?_assertMatch(#dns_rr{ttl = 3600}, erldns_records:minimum_soa_ttl(#dns_rr{ttl = 3600}, #dns_rrdata_a{})),
        ?_assertMatch(#dns_rr{ttl = 30}, erldns_records:minimum_soa_ttl(#dns_rr{ttl = 3600}, #dns_rrdata_soa{minimum = 30})),
        ?_assertMatch(#dns_rr{ttl = 30}, erldns_records:minimum_soa_ttl(#dns_rr{ttl = 30}, #dns_rrdata_soa{minimum = 3600}))
    ].

replace_name_test_() ->
    [
        ?_assertEqual([], lists:map(erldns_records:replace_name(<<"example">>), [])),
        ?_assertMatch(
            [#dns_rr{name = <<"example">>}], lists:map(erldns_records:replace_name(<<"example">>), [#dns_rr{name = <<"test.com">>}])
        )
    ].

match_name_test_() ->
    [
        ?_assert(lists:any(erldns_records:match_name(<<"example.com">>), [#dns_rr{name = <<"example.com">>}])),
        ?_assertNot(lists:any(erldns_records:match_name(<<"example.com">>), [#dns_rr{name = <<"example.net">>}]))
    ].

match_type_test_() ->
    [
        ?_assert(lists:any(erldns_records:match_type(?DNS_TYPE_A), [#dns_rr{type = ?DNS_TYPE_A}])),
        ?_assertNot(lists:any(erldns_records:match_type(?DNS_TYPE_CNAME), [#dns_rr{type = ?DNS_TYPE_A}]))
    ].

match_types_test_() ->
    [
        ?_assert(lists:any(erldns_records:match_types([?DNS_TYPE_A]), [#dns_rr{type = ?DNS_TYPE_A}])),
        ?_assert(lists:any(erldns_records:match_types([?DNS_TYPE_A, ?DNS_TYPE_CNAME]), [#dns_rr{type = ?DNS_TYPE_A}])),
        ?_assertNot(lists:any(erldns_records:match_types([?DNS_TYPE_CNAME]), [#dns_rr{type = ?DNS_TYPE_A}]))
    ].

match_wildcard_test_() ->
    [
        ?_assert(lists:any(erldns_records:match_wildcard(), [#dns_rr{name = <<"*.example.com">>}])),
        ?_assertNot(lists:any(erldns_records:match_wildcard(), [#dns_rr{name = <<"www.example.com">>}]))
    ].

match_delegation_test_() ->
    [
        ?_assert(
            lists:any(erldns_records:match_delegation(<<"ns1.example.com">>), [
                #dns_rr{data = #dns_rrdata_ns{dname = <<"ns1.example.com">>}}
            ])
        ),
        ?_assertNot(
            lists:any(erldns_records:match_delegation(<<"ns1.example.com">>), [
                #dns_rr{data = #dns_rrdata_ns{dname = <<"ns2.example.com">>}}
            ])
        )
    ].

match_wildcard_label_test_() ->
    [
        ?_assert(lists:any(erldns_records:match_wildcard_label(), dns:dname_to_labels(<<"*.example.com">>))),
        ?_assertNot(lists:any(erldns_records:match_wildcard_label(), dns:dname_to_labels(<<"www.example.com">>)))
    ].
