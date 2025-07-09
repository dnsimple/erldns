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
        resolve_authoritative_zone_cut_with_cnames
    ].

%% Tests
resolve_authoritative_host_not_found(_) ->
    erldns_zone_cache:start_link(),
    ZoneName = dns:dname_to_lower(~"resolve_auth_no_host.com"),
    ZoneLabels = dns:dname_to_labels(ZoneName),
    Z = #zone{
        labels = ZoneLabels,
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
    ZoneName = dns:dname_to_lower(~"resolve_auth_zone_cut.com"),
    ZoneLabels = dns:dname_to_labels(ZoneName),
    Z = #zone{
        labels = ZoneLabels,
        name = ZoneName,
        authority = [#dns_rr{name = ~"resolve_auth_zone_cut.com", type = ?DNS_TYPE_SOA}],
        records = NSRecord
    },
    Msg = #dns_message{questions = [#dns_query{name = Qname, type = Qtype = ?DNS_TYPE_A}]},
    erldns_zone_cache:put_zone(Z),
    A = erldns_resolver:resolve_authoritative(Msg, Z, Qname, dns:dname_to_labels(Qname), Qtype, []),
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
    ZoneName = dns:dname_to_lower(~"resolve_auth_zone_cut_cnames.com"),
    ZoneLabels = dns:dname_to_labels(ZoneName),
    Z = #zone{
        labels = ZoneLabels,
        name = ZoneName,
        authority = [#dns_rr{name = ~"resolve_auth_zone_cut_cnames.com", type = ?DNS_TYPE_SOA}],
        records = NSRecord ++ CnameRecords
    },
    Msg = #dns_message{questions = [#dns_query{name = Qname, type = Qtype = ?DNS_TYPE_A}]},
    erldns_zone_cache:put_zone(Z),
    A = erldns_resolver:resolve_authoritative(Msg, Z, Qname, dns:dname_to_labels(Qname), Qtype, []),
    ?assertEqual(false, A#dns_message.aa),
    ?assertEqual(?DNS_RCODE_NOERROR, A#dns_message.rc),
    ?assertEqual(NSRecord, A#dns_message.authority),
    ?assertEqual(CnameRecords, A#dns_message.answers),
    erldns_zone_cache:delete_zone(ZoneName).
