-module(edns_payload_size_SUITE).
-compile([export_all, nowarn_export_all]).

-behaviour(ct_suite).

-define(MAX_PACKET_SIZE, 1232).

-include_lib("stdlib/include/assert.hrl").
-include_lib("dns_erlang/include/dns.hrl").

-spec all() -> [ct_suite:ct_test_def()].
all() ->
    [
        {group, all}
    ].

-spec groups() -> [ct_suite:ct_group_def()].
groups() ->
    [
        {all, [parallel], [
            tcp_does_nothing,
            udp_leaves_additional_empty_if_provided_empty,
            udp_replaces_if_below_minimum,
            udp_replaces_if_above_maximum,
            udp_does_nothing_if_reasonable_value
        ]}
    ].

-spec init_per_testcase(ct_suite:ct_testcase(), ct_suite:ct_config()) -> ct_suite:ct_config().
init_per_testcase(_, Config) ->
    erlang:process_flag(trap_exit, true),
    Config.

-spec end_per_testcase(ct_suite:ct_testcase(), ct_suite:ct_config()) -> term().
end_per_testcase(_, Config) ->
    Config.

%% Tests
tcp_does_nothing(_) ->
    Name = ~"example.com",
    Opts = maps:merge(def_opts(), #{transport => tcp}),
    Q = #dns_query{name = Name, type = ?DNS_TYPE_A},
    Ans = #dns_rr{name = Name, type = ?DNS_TYPE_A, data = #dns_rrdata_a{ip = {1, 2, 3, 4}}},
    Ad = #dns_optrr{dnssec = true},
    Msg = #dns_message{
        qc = 1, anc = 1, adc = 1, questions = [Q], answers = [Ans], additional = [Ad]
    },
    ?assertEqual(Msg, erldns_edns_max_payload_size:call(Msg, Opts)).

udp_leaves_additional_empty_if_provided_empty(_) ->
    Name = ~"example.com",
    Opts = maps:merge(def_opts(), #{transport => udp}),
    Q = #dns_query{name = Name, type = ?DNS_TYPE_A},
    Ans = #dns_rr{name = Name, type = ?DNS_TYPE_A, data = #dns_rrdata_a{ip = {1, 2, 3, 4}}},
    Msg = #dns_message{qc = 1, anc = 1, questions = [Q], answers = [Ans]},
    ?assertEqual(Msg, erldns_edns_max_payload_size:call(Msg, Opts)).

udp_replaces_if_below_minimum(_) ->
    Name = ~"example.com",
    Opts = maps:merge(def_opts(), #{transport => udp}),
    Q = #dns_query{name = Name, type = ?DNS_TYPE_A},
    Ans = #dns_rr{name = Name, type = ?DNS_TYPE_A, data = #dns_rrdata_a{ip = {1, 2, 3, 4}}},
    Ad = #dns_optrr{udp_payload_size = 0, dnssec = true},
    Msg = #dns_message{
        qc = 1, anc = 1, adc = 1, questions = [Q], answers = [Ans], additional = [Ad]
    },
    ?assertEqual(
        Msg#dns_message{additional = [Ad#dns_optrr{udp_payload_size = ?MAX_PACKET_SIZE}]},
        erldns_edns_max_payload_size:call(Msg, Opts)
    ).

udp_replaces_if_above_maximum(_) ->
    Name = ~"example.com",
    Opts = maps:merge(def_opts(), #{transport => udp}),
    Q = #dns_query{name = Name, type = ?DNS_TYPE_A},
    Ans = #dns_rr{name = Name, type = ?DNS_TYPE_A, data = #dns_rrdata_a{ip = {1, 2, 3, 4}}},
    Ad = #dns_optrr{udp_payload_size = 999999999, dnssec = true},
    Msg = #dns_message{
        qc = 1, anc = 1, adc = 1, questions = [Q], answers = [Ans], additional = [Ad]
    },
    ?assertEqual(
        Msg#dns_message{additional = [Ad#dns_optrr{udp_payload_size = ?MAX_PACKET_SIZE}]},
        erldns_edns_max_payload_size:call(Msg, Opts)
    ).

udp_does_nothing_if_reasonable_value(_) ->
    Name = ~"example.com",
    Opts = maps:merge(def_opts(), #{transport => udp}),
    Q = #dns_query{name = Name, type = ?DNS_TYPE_A},
    Ans = #dns_rr{name = Name, type = ?DNS_TYPE_A, data = #dns_rrdata_a{ip = {1, 2, 3, 4}}},
    Ad = #dns_optrr{udp_payload_size = ?MAX_PACKET_SIZE, dnssec = true},
    Msg = #dns_message{
        qc = 1, anc = 1, adc = 1, questions = [Q], answers = [Ans], additional = [Ad]
    },
    ?assertEqual(Msg, erldns_edns_max_payload_size:call(Msg, Opts)).

def_opts() ->
    erldns_pipeline:def_opts().
