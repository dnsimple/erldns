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
            rewrite_soa_ttl,
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

rewrite_soa_ttl(_) ->
    Soa = #dns_rr{
        name = ~"example.com",
        type = ?DNS_TYPE_SOA,
        ttl = 3600,
        data = #dns_rrdata_soa{minimum = 300}
    },
    SoaSig = #dns_rr{
        name = ~"example.com",
        type = ?DNS_TYPE_RRSIG,
        ttl = 3600,
        data = #dns_rrdata_rrsig{type_covered = ?DNS_TYPE_SOA, original_ttl = 3600}
    },
    Nsec = #dns_rr{name = ~"a.example.com", type = ?DNS_TYPE_NSEC, ttl = 300},
    NsecSig = #dns_rr{
        name = ~"a.example.com",
        type = ?DNS_TYPE_RRSIG,
        ttl = 300,
        data = #dns_rrdata_rrsig{type_covered = ?DNS_TYPE_NSEC, original_ttl = 300}
    },
    %% RFC 2308 §3: the SOA in the authority section and the RRSIG covering it are trimmed to
    %% the SOA MINIMUM; everything else in the authority section keeps its TTL, and so does the
    %% RRSIG original TTL, which is part of the signed data.
    Negative = #dns_message{authority = [Soa, SoaSig, Nsec, NsecSig]},
    ?assertMatch(
        #dns_message{
            authority = [
                #dns_rr{type = ?DNS_TYPE_SOA, ttl = 300},
                #dns_rr{ttl = 300, data = #dns_rrdata_rrsig{original_ttl = 3600}},
                #dns_rr{type = ?DNS_TYPE_NSEC, ttl = 300},
                #dns_rr{ttl = 300, data = #dns_rrdata_rrsig{type_covered = ?DNS_TYPE_NSEC}}
            ]
        },
        erldns_records:rewrite_soa_ttl(Negative)
    ),
    %% The answer section is left alone: a query for the SOA itself is served with the zone TTL
    %% on both the SOA and its RRSIG.
    Positive = #dns_message{answers = [Soa, SoaSig], authority = []},
    ?assertEqual(Positive, erldns_records:rewrite_soa_ttl(Positive)),
    %% A MINIMUM at or above the SOA TTL changes nothing.
    HighMinimum = Soa#dns_rr{data = #dns_rrdata_soa{minimum = 3600}},
    Untouched = #dns_message{authority = [HighMinimum, SoaSig]},
    ?assertEqual(Untouched, erldns_records:rewrite_soa_ttl(Untouched)),
    %% Applying it again after the DNSSEC pipe appended the RRSIG still trims that RRSIG: the
    %% SOA is already at the MINIMUM, and the RRSIG must follow it.
    Trimmed = #dns_message{authority = [Soa#dns_rr{ttl = 300}, SoaSig]},
    ?assertMatch(
        #dns_message{authority = [#dns_rr{ttl = 300}, #dns_rr{ttl = 300}]},
        erldns_records:rewrite_soa_ttl(Trimmed)
    ),
    %% No SOA in the authority section (a referral) changes nothing.
    Referral = #dns_message{authority = [#dns_rr{type = ?DNS_TYPE_NS, ttl = 3600}]},
    ?assertEqual(Referral, erldns_records:rewrite_soa_ttl(Referral)).
