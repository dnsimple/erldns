-module(resolver_SUITE).
-compile([export_all, nowarn_export_all]).

-behaviour(ct_suite).

-include_lib("stdlib/include/assert.hrl").
-include_lib("dns_erlang/include/dns.hrl").
-include_lib("erldns/include/erldns.hrl").

-define(MAX_RESOLUTION_DEPTH, 32).
-define(ANY_ZONE, ~"minimal-any.example").

-spec all() -> [ct_suite:ct_test_def()].
all() ->
    [
        resolve_authoritative_host_not_found,
        resolve_authoritative_zone_cut,
        resolve_authoritative_zone_cut_with_cnames,
        resolve_authoritative_zone_cut_with_cname_chain_through_wildcard,
        any_at_a_wildcard_cname_is_answered_with_the_cname,
        resolve_authoritative_zone_cut_with_plain_cname_chain,
        resolve_authoritative_zone_cut_drops_occluded_cname,
        resolve_authoritative_self_delegation_trailing_dot_name_mismatch,
        resolve_authoritative_max_depth_returns_servfail,
        resolve_authoritative_ds_at_and_below_a_zone_cut,
        resolve_authoritative_nested_zone_cut_refers_to_the_topmost,
        resolve_drops_the_sections_of_the_request,
        refused_drops_the_sections_of_the_request,
        negative_answers_carry_the_soa_minimum_ttl,
        any_over_udp_is_answered_with_an_hinfo,
        any_keeps_the_cname_or_the_hinfo_of_the_name,
        minimal_any_is_configured_per_transport
    ].

%% Tests
resolve_authoritative_host_not_found(_) ->
    erldns_zone_cache:start_link(),
    ZoneName = dns_domain:to_lower(~"resolve_auth_no_host.com"),
    ZoneLabels = dns_domain:split(ZoneName),
    Z = #zone{
        labels = ZoneLabels,
        reversed_labels = lists:reverse(ZoneLabels),
        name = ZoneName,
        authority = Authority = [#dns_rr{name = ~"resolve_auth_no_host.com", type = ?DNS_TYPE_SOA}]
    },
    Msg = #dns_message{questions = [#dns_query{name = ZoneName, type = ?DNS_TYPE_A}]},
    {A, none} = erldns_resolver:resolve_authoritative(
        Msg, Z, ZoneLabels, ZoneName, ?DNS_TYPE_A, [], ?MAX_RESOLUTION_DEPTH
    ),
    ?assertEqual(true, A#dns_message.aa),
    ?assertEqual(?DNS_RCODE_NXDOMAIN, A#dns_message.rc),
    ?assertEqual(Authority, A#dns_message.authority).

resolve_authoritative_zone_cut(_) ->
    erldns_zone_cache:start_link(),
    Qname = ~"delegated.resolve_auth_zone_cut.com",
    NSRecord = [#dns_rr{name = Qname, type = ?DNS_TYPE_NS}],
    ZoneName = dns_domain:to_lower(~"resolve_auth_zone_cut.com"),
    ZoneLabels = dns_domain:split(ZoneName),
    Z = #zone{
        labels = ZoneLabels,
        reversed_labels = lists:reverse(ZoneLabels),
        name = ZoneName,
        authority = [#dns_rr{name = ~"resolve_auth_zone_cut.com", type = ?DNS_TYPE_SOA}],
        records = NSRecord
    },
    Msg = #dns_message{questions = [#dns_query{name = Qname, type = ?DNS_TYPE_A}]},
    erldns_zone_cache:put_zone(Z),
    {A, Cut} = erldns_resolver:resolve_authoritative(
        Msg, cached(Z), dns_domain:split(Qname), Qname, ?DNS_TYPE_A, [], ?MAX_RESOLUTION_DEPTH
    ),
    ?assertEqual(false, A#dns_message.aa),
    ?assertEqual(?DNS_RCODE_NOERROR, A#dns_message.rc),
    ?assertEqual(NSRecord, A#dns_message.authority),
    ?assertEqual([], A#dns_message.answers),
    ?assertEqual(dns_domain:split(Qname), Cut),
    erldns_zone_cache:delete_zone(ZoneName).

resolve_authoritative_zone_cut_with_cnames(_) ->
    erldns_zone_cache:start_link(),
    Qname = ~"delegated.resolve_auth_zone_cut_cnames.com",
    CnameRecords =
        [
            #dns_rr{
                name = Qname,
                type = ?DNS_TYPE_CNAME,
                data = #dns_rrdata_cname{dname = ~"delegated-ns.resolve_auth_zone_cut_cnames.com"}
            }
        ],
    NSRecord = [
        #dns_rr{name = ~"delegated-ns.resolve_auth_zone_cut_cnames.com", type = ?DNS_TYPE_NS}
    ],
    ZoneName = dns_domain:to_lower(~"resolve_auth_zone_cut_cnames.com"),
    ZoneLabels = dns_domain:split(ZoneName),
    Z = #zone{
        labels = ZoneLabels,
        reversed_labels = lists:reverse(ZoneLabels),
        name = ZoneName,
        authority = [#dns_rr{name = ~"resolve_auth_zone_cut_cnames.com", type = ?DNS_TYPE_SOA}],
        records = NSRecord ++ CnameRecords
    },
    Msg = #dns_message{questions = [#dns_query{name = Qname, type = ?DNS_TYPE_A}]},
    erldns_zone_cache:put_zone(Z),
    {A, Cut} = erldns_resolver:resolve_authoritative(
        Msg, cached(Z), dns_domain:split(Qname), Qname, ?DNS_TYPE_A, [], ?MAX_RESOLUTION_DEPTH
    ),
    ?assertEqual(false, A#dns_message.aa),
    ?assertEqual(?DNS_RCODE_NOERROR, A#dns_message.rc),
    ?assertEqual(NSRecord, A#dns_message.authority),
    ?assertEqual(CnameRecords, A#dns_message.answers),
    ?assertEqual(dns_domain:split(~"delegated-ns.resolve_auth_zone_cut_cnames.com"), Cut),
    erldns_zone_cache:delete_zone(ZoneName).

%% A chain of two CNAMEs in the parent zone where the second hop is matched by a
%% wildcard and the chain terminates at a delegated subzone. Both CNAMEs must
%% appear in the ANSWER section in chain order; previously the first hop was
%% filtered out because maybe_add_zonecut_records keyed the filter off the CNAME
%% target rather than the CNAME owner name.
resolve_authoritative_zone_cut_with_cname_chain_through_wildcard(_) ->
    erldns_zone_cache:start_link(),
    ZoneName = dns_domain:to_lower(~"chain-zone-cut.example"),
    Qname = ~"ffog.chain-zone-cut.example",
    SoaData = #dns_rrdata_soa{
        mname = ~"ns1.chain-zone-cut.example",
        rname = ~"admin.chain-zone-cut.example",
        serial = 1,
        refresh = 3600,
        retry = 600,
        expire = 86400,
        minimum = 300
    },
    SOA = #dns_rr{name = ZoneName, type = ?DNS_TYPE_SOA, ttl = 3600, data = SoaData},
    Cname1 = #dns_rr{
        name = Qname,
        type = ?DNS_TYPE_CNAME,
        ttl = 3600,
        data = #dns_rrdata_cname{dname = ~"ffog.client.chain-zone-cut.example"}
    },
    WildcardCname = #dns_rr{
        name = ~"*.client.chain-zone-cut.example",
        type = ?DNS_TYPE_CNAME,
        ttl = 60,
        data = #dns_rrdata_cname{dname = ~"swarm.dyn.chain-zone-cut.example"}
    },
    %% The wildcard CNAME is instantiated with the queried owner name per RFC 4592 §3.3.1.
    ExpandedWildcardCname = WildcardCname#dns_rr{
        name = ~"ffog.client.chain-zone-cut.example"
    },
    DelegationNS = #dns_rr{
        name = ~"dyn.chain-zone-cut.example",
        type = ?DNS_TYPE_NS,
        ttl = 3600,
        data = #dns_rrdata_ns{dname = ~"ns-ext.example."}
    },
    Z = erldns_zone_codec:build_zone(
        ZoneName, ~"digest", [SOA, Cname1, WildcardCname, DelegationNS], []
    ),
    ok = erldns_zone_cache:put_zone(Z),
    Msg = #dns_message{questions = [#dns_query{name = Qname, type = ?DNS_TYPE_A}]},
    {A, Cut} = erldns_resolver:resolve_authoritative(
        Msg, cached(Z), dns_domain:split(Qname), Qname, ?DNS_TYPE_A, [], ?MAX_RESOLUTION_DEPTH
    ),
    ?assertEqual(false, A#dns_message.aa),
    ?assertEqual(?DNS_RCODE_NOERROR, A#dns_message.rc),
    ?assertEqual([DelegationNS], A#dns_message.authority),
    ?assertEqual([Cname1, ExpandedWildcardCname], A#dns_message.answers),
    ?assertEqual(dns_domain:split(~"dyn.chain-zone-cut.example"), Cut),
    erldns_zone_cache:delete_zone(ZoneName).

%% ANY matches every type, CNAME included (RFC 1034 §3.7.1), so a CNAME answers ANY and is not
%% followed: step 3a of RFC 1034 §4.3.2 for a name that owns one, step 3c as amended by RFC 4592
%% §3.3.3 for a name a wildcard CNAME matches.
any_at_a_wildcard_cname_is_answered_with_the_cname(_) ->
    erldns_zone_cache:start_link(),
    ZoneName = dns_domain:to_lower(~"wildcard-cname-any.example"),
    QName = ~"www.wildcard-cname-any.example",
    Cname = #dns_rr{
        name = ~"*.wildcard-cname-any.example",
        type = ?DNS_TYPE_CNAME,
        ttl = 3600,
        data = #dns_rrdata_cname{dname = ZoneName}
    },
    A = #dns_rr{
        name = ZoneName, type = ?DNS_TYPE_A, ttl = 3600, data = #dns_rrdata_a{ip = {192, 0, 2, 1}}
    },
    Z = erldns_zone_codec:build_zone(ZoneName, ~"digest", [soa(ZoneName), Cname, A], []),
    ok = erldns_zone_cache:put_zone(Z),
    Expanded = Cname#dns_rr{name = QName},
    {Answer, none} = resolve_authoritative(Z, QName, ?DNS_TYPE_ANY),
    ?assertMatch(#dns_message{aa = true, answers = [Expanded]}, Answer),
    erldns_zone_cache:delete_zone(ZoneName).

%% Plain 2-hop CNAME chain (no wildcard) terminating at a delegated zonecut.
%% Both CNAMEs are owned in the parent zone; only the last hop's target crosses
%% the cut. This is the simplest reproducer of the owner-vs-target filter bug,
%% isolated from the RFC 4592 wildcard mechanics covered by the chain-through-
%% wildcard test above.
resolve_authoritative_zone_cut_with_plain_cname_chain(_) ->
    erldns_zone_cache:start_link(),
    ZoneName = dns_domain:to_lower(~"plain-chain-zone-cut.example"),
    Qname = ~"a.plain-chain-zone-cut.example",
    SoaData = #dns_rrdata_soa{
        mname = ~"ns1.plain-chain-zone-cut.example",
        rname = ~"admin.plain-chain-zone-cut.example",
        serial = 1,
        refresh = 3600,
        retry = 600,
        expire = 86400,
        minimum = 300
    },
    SOA = #dns_rr{name = ZoneName, type = ?DNS_TYPE_SOA, ttl = 3600, data = SoaData},
    Cname1 = #dns_rr{
        name = Qname,
        type = ?DNS_TYPE_CNAME,
        ttl = 3600,
        data = #dns_rrdata_cname{dname = ~"b.plain-chain-zone-cut.example"}
    },
    Cname2 = #dns_rr{
        name = ~"b.plain-chain-zone-cut.example",
        type = ?DNS_TYPE_CNAME,
        ttl = 3600,
        data = #dns_rrdata_cname{dname = ~"target.delegated.plain-chain-zone-cut.example"}
    },
    DelegationNS = #dns_rr{
        name = ~"delegated.plain-chain-zone-cut.example",
        type = ?DNS_TYPE_NS,
        ttl = 3600,
        data = #dns_rrdata_ns{dname = ~"ns-ext.example."}
    },
    Z = erldns_zone_codec:build_zone(
        ZoneName, ~"digest", [SOA, Cname1, Cname2, DelegationNS], []
    ),
    ok = erldns_zone_cache:put_zone(Z),
    Msg = #dns_message{questions = [#dns_query{name = Qname, type = ?DNS_TYPE_A}]},
    {A, Cut} = erldns_resolver:resolve_authoritative(
        Msg, cached(Z), dns_domain:split(Qname), Qname, ?DNS_TYPE_A, [], ?MAX_RESOLUTION_DEPTH
    ),
    ?assertEqual(false, A#dns_message.aa),
    ?assertEqual(?DNS_RCODE_NOERROR, A#dns_message.rc),
    ?assertEqual([DelegationNS], A#dns_message.authority),
    ?assertEqual([Cname1, Cname2], A#dns_message.answers),
    ?assertEqual(dns_domain:split(~"delegated.plain-chain-zone-cut.example"), Cut),
    erldns_zone_cache:delete_zone(ZoneName).

%% Occluded data (RFC 5936 §3.5, RFC 2181 §6): records whose owner sits below a
%% zone cut in the parent zone MUST NOT be served by the parent. If the
%% maybe_add_zonecut_records filter ever regresses back to keying off the CNAME
%% target instead of the owner, a CNAME owned below the cut whose target is
%% also below the cut would leak into the answer section. This test pins the
%% owner-based behavior so that regression would fail loudly.
resolve_authoritative_zone_cut_drops_occluded_cname(_) ->
    erldns_zone_cache:start_link(),
    ZoneName = dns_domain:to_lower(~"occluded-cname.example"),
    Qname = ~"occluded.delegated.occluded-cname.example",
    SoaData = #dns_rrdata_soa{
        mname = ~"ns1.occluded-cname.example",
        rname = ~"admin.occluded-cname.example",
        serial = 1,
        refresh = 3600,
        retry = 600,
        expire = 86400,
        minimum = 300
    },
    SOA = #dns_rr{name = ZoneName, type = ?DNS_TYPE_SOA, ttl = 3600, data = SoaData},
    %% CNAME whose owner AND target both sit below the delegated cut.
    OccludedCname = #dns_rr{
        name = Qname,
        type = ?DNS_TYPE_CNAME,
        ttl = 3600,
        data = #dns_rrdata_cname{
            dname = ~"sibling.delegated.occluded-cname.example"
        }
    },
    DelegationNS = #dns_rr{
        name = ~"delegated.occluded-cname.example",
        type = ?DNS_TYPE_NS,
        ttl = 3600,
        data = #dns_rrdata_ns{dname = ~"ns-ext.example."}
    },
    Z = erldns_zone_codec:build_zone(
        ZoneName, ~"digest", [SOA, OccludedCname, DelegationNS], []
    ),
    ok = erldns_zone_cache:put_zone(Z),
    Msg = #dns_message{questions = [#dns_query{name = Qname, type = ?DNS_TYPE_A}]},
    {A, Cut} = erldns_resolver:resolve_authoritative(
        Msg, cached(Z), dns_domain:split(Qname), Qname, ?DNS_TYPE_A, [], ?MAX_RESOLUTION_DEPTH
    ),
    ?assertEqual(false, A#dns_message.aa),
    ?assertEqual(?DNS_RCODE_NOERROR, A#dns_message.rc),
    ?assertEqual([DelegationNS], A#dns_message.authority),
    ?assertEqual([], A#dns_message.answers),
    ?assertEqual(dns_domain:split(~"delegated.occluded-cname.example"), Cut),
    erldns_zone_cache:delete_zone(ZoneName).

%% NS at the same name as the answer (self-delegation) must be detected even when
%% the A record owner name and the NS RR owner name differ only by a trailing dot.
%% Without label-based comparison, restart_delegated_query/5 loops forever.
resolve_authoritative_self_delegation_trailing_dot_name_mismatch(_) ->
    erldns_zone_cache:start_link(),
    ZoneName = dns_domain:to_lower(~"self-deleg-trailing-dot.example"),
    %% A record owner name WITH trailing dot; NS owner WITHOUT — same labels, distinct binaries
    ARecordOwnerName = ~"ns2.self-deleg-trailing-dot.example.",
    NsOwnerName = ~"ns2.self-deleg-trailing-dot.example",
    SelfNsTarget = ~"ns2.self-deleg-trailing-dot.example.",
    Qname = dns_domain:to_lower(~"ns2.self-deleg-trailing-dot.example"),
    QLabels = dns_domain:split(Qname),
    ?assert(
        dns_domain:are_equal_labels(
            dns_domain:split(NsOwnerName),
            dns_domain:split(ARecordOwnerName)
        )
    ),
    SoaData = #dns_rrdata_soa{
        mname = ~"ns1.self-deleg-trailing-dot.example",
        rname = ~"admin.self-deleg-trailing-dot.example",
        serial = 1,
        refresh = 3600,
        retry = 600,
        expire = 86400,
        minimum = 300
    },
    SOA = #dns_rr{name = ZoneName, type = ?DNS_TYPE_SOA, ttl = 3600, data = SoaData},
    ARR = #dns_rr{
        name = ARecordOwnerName,
        type = ?DNS_TYPE_A,
        ttl = 3600,
        data = #dns_rrdata_a{ip = {192, 0, 2, 1}}
    },
    NS = #dns_rr{
        name = NsOwnerName,
        type = ?DNS_TYPE_NS,
        ttl = 3600,
        data = #dns_rrdata_ns{dname = SelfNsTarget}
    },
    Z = erldns_zone_codec:build_zone(ZoneName, ~"digest", [SOA, ARR, NS], []),
    ok = erldns_zone_cache:put_zone(Z),
    Msg = #dns_message{questions = [#dns_query{name = Qname, type = ?DNS_TYPE_A}]},
    Parent = self(),
    Pid =
        spawn(fun() ->
            try
                {R, _} = erldns_resolver:resolve_authoritative(
                    Msg, cached(Z), QLabels, Qname, ?DNS_TYPE_A, [], ?MAX_RESOLUTION_DEPTH
                ),
                Parent ! {ok, R}
            catch
                Class:Reason:Stack ->
                    Parent ! {caught, Class, Reason, Stack}
            end
        end),
    receive
        {ok, Res} ->
            ?assertEqual(false, Res#dns_message.aa),
            ?assertEqual(?DNS_RCODE_NOERROR, Res#dns_message.rc),
            ?assertMatch([_ | _], Res#dns_message.authority)
    after 2000 ->
        exit(Pid, kill),
        ?assert(false, "resolve_authoritative should finish within 2s (infinite delegation loop?)")
    end,
    erldns_zone_cache:delete_zone(ZoneName).

%% A CNAME chain longer than ?MAX_RESOLUTION_DEPTH must return SERVFAIL
%% instead of looping indefinitely. Each CNAME target is unique so the
%% existing CNAME-loop detector (lists:member/2) will not fire — only
%% the depth counter prevents runaway recursion.
resolve_authoritative_max_depth_returns_servfail(_) ->
    erldns_zone_cache:start_link(),
    ZoneName = dns_domain:to_lower(~"deep-cname.example"),
    ChainLen = ?MAX_RESOLUTION_DEPTH + 1,
    SoaData = #dns_rrdata_soa{
        mname = ~"ns1.deep-cname.example",
        rname = ~"admin.deep-cname.example",
        serial = 1,
        refresh = 3600,
        retry = 600,
        expire = 86400,
        minimum = 300
    },
    SOA = #dns_rr{name = ZoneName, type = ?DNS_TYPE_SOA, ttl = 3600, data = SoaData},
    %% Build CNAME chain: link0 -> link1 -> link2 -> ... -> linkN
    %% linkN has no A record, but we'll never get there — depth runs out first.
    CnameRecords = lists:map(
        fun(I) ->
            Name = iolist_to_binary([
                "link", integer_to_binary(I), ".deep-cname.example"
            ]),
            Target = iolist_to_binary([
                "link", integer_to_binary(I + 1), ".deep-cname.example"
            ]),
            #dns_rr{
                name = Name,
                type = ?DNS_TYPE_CNAME,
                ttl = 3600,
                data = #dns_rrdata_cname{dname = Target}
            }
        end,
        lists:seq(0, ChainLen - 1)
    ),
    Z = erldns_zone_codec:build_zone(ZoneName, ~"digest", [SOA | CnameRecords], []),
    ok = erldns_zone_cache:put_zone(Z),
    Qname = ~"link0.deep-cname.example",
    QLabels = dns_domain:split(Qname),
    Msg = #dns_message{questions = [#dns_query{name = Qname, type = ?DNS_TYPE_A}]},
    {Res, none} = erldns_resolver:resolve_authoritative(
        Msg, cached(Z), QLabels, Qname, ?DNS_TYPE_A, [], ?MAX_RESOLUTION_DEPTH
    ),
    ?assertEqual(?DNS_RCODE_SERVFAIL, Res#dns_message.rc),
    erldns_zone_cache:delete_zone(ZoneName).

%% RFC 4035 §3.1.4.1: the DS RRset is the parent's, so a DS query for the delegation name is
%% answered here, even when the delegation's NS points at that name; a DS query for anything
%% below the cut is a referral like any other query there, and so is one at the cut for any
%% other type.
resolve_authoritative_ds_at_and_below_a_zone_cut(_) ->
    erldns_zone_cache:start_link(),
    ZoneName = dns_domain:to_lower(~"ds-zone-cut.example"),
    Cut = ~"delegated.ds-zone-cut.example",
    Below = ~"ns1.delegated.ds-zone-cut.example",
    NS = #dns_rr{name = Cut, type = ?DNS_TYPE_NS, ttl = 3600, data = #dns_rrdata_ns{dname = Cut}},
    DS = #dns_rr{
        name = Cut,
        type = ?DNS_TYPE_DS,
        ttl = 3600,
        data = #dns_rrdata_ds{keytag = 1, alg = 8, digest_type = 2, digest = <<0:256>>}
    },
    Glue = #dns_rr{
        name = Cut, type = ?DNS_TYPE_A, ttl = 3600, data = #dns_rrdata_a{ip = {192, 0, 2, 1}}
    },
    BelowGlue = Glue#dns_rr{name = Below, data = #dns_rrdata_a{ip = {192, 0, 2, 2}}},
    Z = erldns_zone_codec:build_zone(
        ZoneName, ~"digest", [soa(ZoneName), NS, DS, Glue, BelowGlue], []
    ),
    ok = erldns_zone_cache:put_zone(Z),
    CutLabels = dns_domain:split(Cut),
    {AtCut, none} = resolve_authoritative(Z, Cut, ?DNS_TYPE_DS),
    ?assertMatch(
        #dns_message{aa = true, rc = ?DNS_RCODE_NOERROR, answers = [DS], authority = []}, AtCut
    ),
    {BelowCut, CutLabels} = resolve_authoritative(Z, Below, ?DNS_TYPE_DS),
    ?assertMatch(
        #dns_message{aa = false, rc = ?DNS_RCODE_NOERROR, answers = [], authority = [NS]}, BelowCut
    ),
    {Referral, CutLabels} = resolve_authoritative(Z, Cut, ?DNS_TYPE_A),
    ?assertMatch(#dns_message{aa = false, answers = [], authority = [NS]}, Referral),
    erldns_zone_cache:delete_zone(ZoneName).

%% A cut under another cut is occluded by it: the referral is to the topmost delegation.
resolve_authoritative_nested_zone_cut_refers_to_the_topmost(_) ->
    erldns_zone_cache:start_link(),
    ZoneName = dns_domain:to_lower(~"nested-zone-cut.example"),
    Outer = #dns_rr{
        name = ~"delegated.nested-zone-cut.example",
        type = ?DNS_TYPE_NS,
        ttl = 3600,
        data = #dns_rrdata_ns{dname = ~"ns-ext.example."}
    },
    Inner = Outer#dns_rr{name = ~"sub.delegated.nested-zone-cut.example"},
    Z = erldns_zone_codec:build_zone(ZoneName, ~"digest", [soa(ZoneName), Outer, Inner], []),
    ok = erldns_zone_cache:put_zone(Z),
    {A, Cut} = resolve_authoritative(Z, ~"www.sub.delegated.nested-zone-cut.example", ?DNS_TYPE_A),
    ?assertEqual(dns_domain:split(~"delegated.nested-zone-cut.example"), Cut),
    ?assertMatch(#dns_message{aa = false, answers = [], authority = [Outer]}, A),
    erldns_zone_cache:delete_zone(ZoneName).

%% RFC 1035 §4.1.1: a query carries nothing of use in its answer and authority sections, and
%% nothing found there makes it into the response.
resolve_drops_the_sections_of_the_request(_) ->
    erldns_zone_cache:start_link(),
    ZoneName = dns_domain:to_lower(~"request-sections.example"),
    QName = ~"a.request-sections.example",
    A = #dns_rr{
        name = QName, type = ?DNS_TYPE_A, ttl = 60, data = #dns_rrdata_a{ip = {192, 0, 2, 1}}
    },
    Planted = #dns_rr{
        name = QName,
        type = ?DNS_TYPE_NS,
        ttl = 1,
        data = #dns_rrdata_ns{dname = ~"ns.attacker.example."}
    },
    Z = erldns_zone_codec:build_zone(ZoneName, ~"digest", [soa(ZoneName), A], []),
    ok = erldns_zone_cache:put_zone(Z),
    Msg = #dns_message{
        questions = [#dns_query{name = QName, type = ?DNS_TYPE_A}],
        answers = [Planted],
        authority = [Planted]
    },
    Opts = erldns_resolver:prepare(#{
        resolved => false, query_labels => dns_domain:split(QName), query_type => ?DNS_TYPE_A
    }),
    {Answer, #{zonecut := none}} = erldns_resolver:call(Msg, Opts),
    ?assertMatch(#dns_message{aa = true, answers = [A], authority = []}, Answer),
    erldns_zone_cache:delete_zone(ZoneName).

%% A name outside every zone is refused, and the request's answer and authority sections are not
%% sent back: a NOTIFY carries an SOA in its answer section.
refused_drops_the_sections_of_the_request(_) ->
    erldns_zone_cache:start_link(),
    QName = ~"refused.example",
    Planted = #dns_rr{
        name = QName, type = ?DNS_TYPE_NS, ttl = 1, data = #dns_rrdata_ns{dname = ~"ns.example."}
    },
    Msg = #dns_message{
        questions = [#dns_query{name = QName, type = ?DNS_TYPE_A}],
        answers = [Planted],
        authority = [Planted]
    },
    Opts = erldns_resolver:prepare(#{
        resolved => false, query_labels => dns_domain:split(QName), query_type => ?DNS_TYPE_A
    }),
    application:set_env(erldns, use_root_hints, false),
    try
        ?assertMatch(
            #dns_message{rc = ?DNS_RCODE_REFUSED, answers = [], authority = []},
            erldns_resolver:call(Msg, Opts)
        )
    after
        application:unset_env(erldns, use_root_hints)
    end.

%% RFC 2308 §3: the SOA in the authority section of a negative answer is served at the minimum
%% of its own TTL and its MINIMUM field, so that resolvers and caches in front of us (an edge
%% packet cache included) hold the negative answer for the negative TTL and not the SOA TTL.
%% A query for the SOA itself is a positive answer and keeps the zone TTL.
negative_answers_carry_the_soa_minimum_ttl(_) ->
    erldns_zone_cache:start_link(),
    ZoneName = dns_domain:to_lower(~"negative-ttl.example"),
    ZoneLabels = dns_domain:split(ZoneName),
    Soa = #dns_rr{
        name = ZoneName,
        type = ?DNS_TYPE_SOA,
        ttl = 3600,
        data = #dns_rrdata_soa{
            mname = ~"ns1.negative-ttl.example",
            rname = ~"admin.negative-ttl.example",
            serial = 1,
            refresh = 86400,
            retry = 7200,
            expire = 604800,
            minimum = 300
        }
    },
    A = #dns_rr{
        name = ~"a.negative-ttl.example",
        type = ?DNS_TYPE_A,
        ttl = 60,
        data = #dns_rrdata_a{ip = {192, 0, 2, 1}}
    },
    Z = #zone{
        labels = ZoneLabels,
        reversed_labels = lists:reverse(ZoneLabels),
        name = ZoneName,
        authority = [Soa],
        records = [Soa, A]
    },
    erldns_zone_cache:put_zone(Z),
    NxDomain = resolve(~"nx.negative-ttl.example", ?DNS_TYPE_A),
    ?assertMatch(
        #dns_message{
            aa = true,
            rc = ?DNS_RCODE_NXDOMAIN,
            answers = [],
            authority = [#dns_rr{type = ?DNS_TYPE_SOA, ttl = 300}]
        },
        NxDomain
    ),
    NoData = resolve(~"a.negative-ttl.example", ?DNS_TYPE_AAAA),
    ?assertMatch(
        #dns_message{
            aa = true,
            rc = ?DNS_RCODE_NOERROR,
            answers = [],
            authority = [#dns_rr{type = ?DNS_TYPE_SOA, ttl = 300}]
        },
        NoData
    ),
    SoaAnswer = resolve(ZoneName, ?DNS_TYPE_SOA),
    ?assertMatch(
        #dns_message{
            aa = true,
            rc = ?DNS_RCODE_NOERROR,
            answers = [#dns_rr{type = ?DNS_TYPE_SOA, ttl = 3600}]
        },
        SoaAnswer
    ),
    erldns_zone_cache:delete_zone(ZoneName).

%% RFC 8482 §4.2: ANY at a name with records gets one HINFO, without glue for the records it
%% replaces; a name without records is answered as for any other type.
any_over_udp_is_answered_with_an_hinfo(_) ->
    ZoneName = put_any_zone(),
    Ede = #dns_opt_ede{info_code = ?DNS_EDE_NOT_SUPPORTED},
    Apex = hinfo(ZoneName, 3600),
    ?assertMatch(
        #dns_message{
            aa = true,
            rc = ?DNS_RCODE_NOERROR,
            answers = [Apex],
            additional = [#dns_optrr{data = [Ede]}]
        },
        resolve(ZoneName, ?DNS_TYPE_ANY)
    ),
    Wild = hinfo(~"a.wild.minimal-any.example", 3600),
    ?assertMatch(
        #dns_message{answers = [Wild]}, resolve(~"a.wild.minimal-any.example", ?DNS_TYPE_ANY)
    ),
    ?assertMatch(
        #dns_message{rc = ?DNS_RCODE_NXDOMAIN, answers = [], additional = [#dns_optrr{data = []}]},
        resolve(~"nx.minimal-any.example", ?DNS_TYPE_ANY)
    ),
    erldns_zone_cache:delete_zone(ZoneName).

%% A CNAME is the only record at its name, and an HINFO RRset is not masked by a synthesised one
%% (RFC 8482 §6).
any_keeps_the_cname_or_the_hinfo_of_the_name(_) ->
    ZoneName = put_any_zone(),
    ?assertMatch(
        #dns_message{
            answers = [#dns_rr{type = ?DNS_TYPE_CNAME}], additional = [#dns_optrr{data = []}]
        },
        resolve(~"cname.minimal-any.example", ?DNS_TYPE_ANY)
    ),
    Host = #dns_rrdata_hinfo{cpu = ~"x86", os = ~"Linux"},
    ?assertMatch(
        #dns_message{
            answers = [#dns_rr{type = ?DNS_TYPE_HINFO, data = Host}],
            additional = [#dns_optrr{data = [#dns_opt_ede{}]}]
        },
        resolve(~"host.minimal-any.example", ?DNS_TYPE_ANY)
    ),
    erldns_zone_cache:delete_zone(ZoneName).

%% By default ANY over TCP gets every record at the name, and their glue.
minimal_any_is_configured_per_transport(_) ->
    ZoneName = put_any_zone(),
    Full = [
        {ZoneName, ?DNS_TYPE_SOA},
        {ZoneName, ?DNS_TYPE_NS},
        {ZoneName, ?DNS_TYPE_MX},
        {~"mail.minimal-any.example", ?DNS_TYPE_A},
        {~"ns1.minimal-any.example", ?DNS_TYPE_A}
    ],
    Tcp = resolve(ZoneName, ?DNS_TYPE_ANY, tcp),
    ?assertEqual(lists:sort(Full), names_and_types(Tcp)),
    application:set_env(erldns, minimal_any, #{udp => false, tcp => true, hinfo_ttl => 60}),
    try
        Udp = resolve(ZoneName, ?DNS_TYPE_ANY, udp),
        ?assertEqual(lists:sort(Full), names_and_types(Udp)),
        Apex = hinfo(ZoneName, 60),
        ?assertMatch(#dns_message{answers = [Apex]}, resolve(ZoneName, ?DNS_TYPE_ANY, tcp))
    after
        application:unset_env(erldns, minimal_any),
        erldns_zone_cache:delete_zone(ZoneName)
    end.

%% Drive the resolver pipe the way the pipeline does, so `complete_response/1' runs.
resolve(QName, QType) ->
    resolve(QName, QType, udp).

resolve(QName, QType, Transport) ->
    Msg = #dns_message{
        questions = [#dns_query{name = QName, type = QType}], additional = [#dns_optrr{}]
    },
    Opts = erldns_resolver:prepare(#{
        resolved => false,
        query_labels => dns_domain:split(QName),
        query_type => QType,
        transport => Transport
    }),
    {Answer, _} = erldns_resolver:call(Msg, Opts),
    Answer.

put_any_zone() ->
    erldns_zone_cache:start_link(),
    ok = erldns_zone_cache:put_zone(any_zone()),
    ?ANY_ZONE.

%% Records whose answers to ANY differ: an apex with glue for its NS and MX, a CNAME, a name with
%% its own HINFO, and a wildcard.
any_zone() ->
    RR = fun(Name, Type, Data) -> #dns_rr{name = Name, type = Type, ttl = 3600, data = Data} end,
    Records = [
        soa(?ANY_ZONE),
        RR(?ANY_ZONE, ?DNS_TYPE_NS, #dns_rrdata_ns{dname = ~"ns1.minimal-any.example"}),
        RR(?ANY_ZONE, ?DNS_TYPE_MX, #dns_rrdata_mx{
            preference = 10, exchange = ~"mail.minimal-any.example"
        }),
        RR(~"ns1.minimal-any.example", ?DNS_TYPE_A, #dns_rrdata_a{ip = {192, 0, 2, 1}}),
        RR(~"mail.minimal-any.example", ?DNS_TYPE_A, #dns_rrdata_a{ip = {192, 0, 2, 2}}),
        RR(~"cname.minimal-any.example", ?DNS_TYPE_CNAME, #dns_rrdata_cname{dname = ?ANY_ZONE}),
        RR(~"host.minimal-any.example", ?DNS_TYPE_HINFO, #dns_rrdata_hinfo{
            cpu = ~"x86", os = ~"Linux"
        }),
        RR(~"host.minimal-any.example", ?DNS_TYPE_A, #dns_rrdata_a{ip = {192, 0, 2, 3}}),
        RR(~"*.wild.minimal-any.example", ?DNS_TYPE_A, #dns_rrdata_a{ip = {192, 0, 2, 4}})
    ],
    erldns_zone_codec:build_zone(?ANY_ZONE, ~"digest", Records, []).

hinfo(Name, TTL) ->
    Data = #dns_rrdata_hinfo{cpu = ~"RFC8482", os = ~""},
    #dns_rr{name = Name, type = ?DNS_TYPE_HINFO, ttl = TTL, data = Data}.

names_and_types(#dns_message{answers = Answers, additional = Additional}) ->
    lists:sort([{Name, Type} || #dns_rr{name = Name, type = Type} <- Answers ++ Additional]).

resolve_authoritative(Z, QName, QType) ->
    Msg = #dns_message{questions = [#dns_query{name = QName, type = QType}]},
    erldns_resolver:resolve_authoritative(
        Msg, cached(Z), dns_domain:split(QName), QName, QType, [], ?MAX_RESOLUTION_DEPTH
    ).

%% Lookups go through the generation of a header read from the cache, not of one built by hand.
cached(#zone{name = Name}) ->
    erldns_zone_cache:lookup_zone(dns_domain:to_lower(Name)).

soa(ZoneName) ->
    #dns_rr{
        name = ZoneName,
        type = ?DNS_TYPE_SOA,
        ttl = 3600,
        data = #dns_rrdata_soa{
            mname = <<"ns1.", ZoneName/binary>>,
            rname = <<"admin.", ZoneName/binary>>,
            serial = 1,
            refresh = 3600,
            retry = 600,
            expire = 86400,
            minimum = 300
        }
    }.
