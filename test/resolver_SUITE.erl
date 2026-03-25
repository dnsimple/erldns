-module(resolver_SUITE).
-compile([export_all, nowarn_export_all]).

-behaviour(ct_suite).

-include_lib("stdlib/include/assert.hrl").
-include_lib("dns_erlang/include/dns.hrl").
-include_lib("erldns/include/erldns.hrl").

-spec all() -> [ct_suite:ct_test_def()].
all() ->
    [
        resolve_authoritative_host_not_found,
        resolve_authoritative_zone_cut,
        resolve_authoritative_zone_cut_with_cnames,
        resolve_authoritative_self_delegation_trailing_dot_name_mismatch
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
    A = erldns_resolver:resolve_authoritative(Msg, Z, ZoneName, ZoneLabels, Qtype, []),
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
    A = erldns_resolver:resolve_authoritative(Msg, Z, Qname, dns_domain:split(Qname), Qtype, []),
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
    A = erldns_resolver:resolve_authoritative(Msg, Z, Qname, dns_domain:split(Qname), Qtype, []),
    ?assertEqual(false, A#dns_message.aa),
    ?assertEqual(?DNS_RCODE_NOERROR, A#dns_message.rc),
    ?assertEqual(NSRecord, A#dns_message.authority),
    ?assertEqual(CnameRecords, A#dns_message.answers),
    erldns_zone_cache:delete_zone(ZoneName).

%% NS at the same name as the answer (self-delegation) must be detected even when
%% the A record owner name and the NS RR owner name differ only by a trailing dot.
%% Without label-based comparison, restart_delegated_query/5 loops forever.
resolve_authoritative_self_delegation_trailing_dot_name_mismatch(_) ->
    erldns_zone_cache:start_link(),
    erldns_handler:start_link(),
    ZoneName = dns_domain:to_lower(~"self-deleg-trailing-dot.example"),
    %% A record owner name WITH trailing dot; NS owner WITHOUT — same labels, distinct binaries
    ARecordOwnerName = <<"ns2.self-deleg-trailing-dot.example.">>,
    NsOwnerName = <<"ns2.self-deleg-trailing-dot.example">>,
    SelfNsTarget = <<"ns2.self-deleg-trailing-dot.example.">>,
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
                R = erldns_resolver:resolve_authoritative(Msg, Z, QLabels, Qname, ?DNS_TYPE_A, []),
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
