-module(resolver_SUITE).
-compile([export_all, nowarn_export_all]).

-behaviour(ct_suite).

-include_lib("stdlib/include/assert.hrl").
-include_lib("dns_erlang/include/dns.hrl").
-include_lib("erldns/include/erldns.hrl").

-define(MAX_RESOLUTION_DEPTH, 32).

-spec all() -> [ct_suite:ct_test_def()].
all() ->
    [
        resolve_authoritative_host_not_found,
        resolve_authoritative_zone_cut,
        resolve_authoritative_zone_cut_with_cnames,
        resolve_authoritative_zone_cut_with_cname_chain_through_wildcard,
        resolve_authoritative_zone_cut_with_plain_cname_chain,
        resolve_authoritative_zone_cut_drops_occluded_cname,
        resolve_authoritative_self_delegation_trailing_dot_name_mismatch,
        resolve_authoritative_max_depth_returns_servfail
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
    Msg = #dns_message{questions = [#dns_query{name = ZoneName, type = Qtype = ?DNS_TYPE_A}]},
    A = erldns_resolver:resolve_authoritative(
        Msg, Z, ZoneName, ZoneLabels, Qtype, [], ?MAX_RESOLUTION_DEPTH
    ),
    ?assertEqual(true, A#dns_message.aa),
    ?assertEqual(?DNS_RCODE_NXDOMAIN, A#dns_message.rc),
    ?assertEqual(Authority, A#dns_message.authority).

resolve_authoritative_zone_cut(_) ->
    erldns_zone_cache:start_link(),
    erldns_handler:start_link(),
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
    Msg = #dns_message{questions = [#dns_query{name = Qname, type = Qtype = ?DNS_TYPE_A}]},
    erldns_zone_cache:put_zone(Z),
    A = erldns_resolver:resolve_authoritative(
        Msg, Z, Qname, dns_domain:split(Qname), Qtype, [], ?MAX_RESOLUTION_DEPTH
    ),
    ?assertEqual(false, A#dns_message.aa),
    ?assertEqual(?DNS_RCODE_NOERROR, A#dns_message.rc),
    ?assertEqual(NSRecord, A#dns_message.authority),
    ?assertEqual([], A#dns_message.answers),
    erldns_zone_cache:delete_zone(ZoneName).

resolve_authoritative_zone_cut_with_cnames(_) ->
    erldns_zone_cache:start_link(),
    erldns_handler:start_link(),
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
    Msg = #dns_message{questions = [#dns_query{name = Qname, type = Qtype = ?DNS_TYPE_A}]},
    erldns_zone_cache:put_zone(Z),
    A = erldns_resolver:resolve_authoritative(
        Msg, Z, Qname, dns_domain:split(Qname), Qtype, [], ?MAX_RESOLUTION_DEPTH
    ),
    ?assertEqual(false, A#dns_message.aa),
    ?assertEqual(?DNS_RCODE_NOERROR, A#dns_message.rc),
    ?assertEqual(NSRecord, A#dns_message.authority),
    ?assertEqual(CnameRecords, A#dns_message.answers),
    erldns_zone_cache:delete_zone(ZoneName).

%% A chain of two CNAMEs in the parent zone where the second hop is matched by a
%% wildcard and the chain terminates at a delegated subzone. Both CNAMEs must
%% appear in the ANSWER section in chain order; previously the first hop was
%% filtered out because maybe_add_zonecut_records keyed the filter off the CNAME
%% target rather than the CNAME owner name.
resolve_authoritative_zone_cut_with_cname_chain_through_wildcard(_) ->
    erldns_zone_cache:start_link(),
    erldns_handler:start_link(),
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
    A = erldns_resolver:resolve_authoritative(
        Msg, Z, Qname, dns_domain:split(Qname), ?DNS_TYPE_A, [], ?MAX_RESOLUTION_DEPTH
    ),
    ?assertEqual(false, A#dns_message.aa),
    ?assertEqual(?DNS_RCODE_NOERROR, A#dns_message.rc),
    ?assertEqual([DelegationNS], A#dns_message.authority),
    ?assertEqual([Cname1, ExpandedWildcardCname], A#dns_message.answers),
    erldns_zone_cache:delete_zone(ZoneName).

%% Plain 2-hop CNAME chain (no wildcard) terminating at a delegated zonecut.
%% Both CNAMEs are owned in the parent zone; only the last hop's target crosses
%% the cut. This is the simplest reproducer of the owner-vs-target filter bug,
%% isolated from the RFC 4592 wildcard mechanics covered by the chain-through-
%% wildcard test above.
resolve_authoritative_zone_cut_with_plain_cname_chain(_) ->
    erldns_zone_cache:start_link(),
    erldns_handler:start_link(),
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
    A = erldns_resolver:resolve_authoritative(
        Msg, Z, Qname, dns_domain:split(Qname), ?DNS_TYPE_A, [], ?MAX_RESOLUTION_DEPTH
    ),
    ?assertEqual(false, A#dns_message.aa),
    ?assertEqual(?DNS_RCODE_NOERROR, A#dns_message.rc),
    ?assertEqual([DelegationNS], A#dns_message.authority),
    ?assertEqual([Cname1, Cname2], A#dns_message.answers),
    erldns_zone_cache:delete_zone(ZoneName).

%% Occluded data (RFC 5936 §3.5, RFC 2181 §6): records whose owner sits below a
%% zone cut in the parent zone MUST NOT be served by the parent. If the
%% maybe_add_zonecut_records filter ever regresses back to keying off the CNAME
%% target instead of the owner, a CNAME owned below the cut whose target is
%% also below the cut would leak into the answer section. This test pins the
%% owner-based behavior so that regression would fail loudly.
resolve_authoritative_zone_cut_drops_occluded_cname(_) ->
    erldns_zone_cache:start_link(),
    erldns_handler:start_link(),
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
    A = erldns_resolver:resolve_authoritative(
        Msg, Z, Qname, dns_domain:split(Qname), ?DNS_TYPE_A, [], ?MAX_RESOLUTION_DEPTH
    ),
    ?assertEqual(false, A#dns_message.aa),
    ?assertEqual(?DNS_RCODE_NOERROR, A#dns_message.rc),
    ?assertEqual([DelegationNS], A#dns_message.authority),
    ?assertEqual([], A#dns_message.answers),
    erldns_zone_cache:delete_zone(ZoneName).

%% NS at the same name as the answer (self-delegation) must be detected even when
%% the A record owner name and the NS RR owner name differ only by a trailing dot.
%% Without label-based comparison, restart_delegated_query/5 loops forever.
resolve_authoritative_self_delegation_trailing_dot_name_mismatch(_) ->
    erldns_zone_cache:start_link(),
    erldns_handler:start_link(),
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
                R = erldns_resolver:resolve_authoritative(
                    Msg, Z, QLabels, Qname, ?DNS_TYPE_A, [], ?MAX_RESOLUTION_DEPTH
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
    erldns_handler:start_link(),
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
    Res = erldns_resolver:resolve_authoritative(
        Msg, Z, QLabels, Qname, ?DNS_TYPE_A, [], ?MAX_RESOLUTION_DEPTH
    ),
    ?assertEqual(?DNS_RCODE_SERVFAIL, Res#dns_message.rc),
    erldns_zone_cache:delete_zone(ZoneName).
