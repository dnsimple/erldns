-module(edns_SUITE).
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
            {group, payload_size},
            {group, ede_tests}
        ]},
        {payload_size, [parallel], [
            tcp_does_nothing,
            udp_leaves_additional_empty_if_provided_empty,
            udp_replaces_if_below_minimum,
            udp_replaces_if_above_maximum,
            udp_does_nothing_if_reasonable_value
        ]},
        {ede_tests, [parallel], [
            ede_extraction,
            ede_pipeline_nxdomain_no_ede,
            ede_pipeline_noerror_no_ede,
            ede_pipeline_refused,
            ede_pipeline_servfail,
            ede_pipeline_creates_optrr,
            ede_pipeline_appends_to_optrr
        ]}
    ].

-spec init_per_suite(ct_suite:ct_config()) -> ct_suite:ct_config().
init_per_suite(Config) ->
    application:unset_env(erldns, edns_ede),
    Config.

-spec end_per_suite(ct_suite:ct_config()) -> term().
end_per_suite(Config) ->
    application:unset_env(erldns, edns_ede),
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
tcp_does_nothing(_) ->
    Name = ~"example.com",
    Opts = def_opts(#{transport => tcp}),
    Q = #dns_query{name = Name, type = ?DNS_TYPE_A},
    Ans = #dns_rr{name = Name, type = ?DNS_TYPE_A, data = #dns_rrdata_a{ip = {1, 2, 3, 4}}},
    Ad = #dns_optrr{dnssec = true},
    Msg = #dns_message{
        qc = 1, anc = 1, adc = 1, questions = [Q], answers = [Ans], additional = [Ad]
    },
    ?assertEqual(Msg, erldns_edns_max_payload_size:call(Msg, Opts)).

udp_leaves_additional_empty_if_provided_empty(_) ->
    Name = ~"example.com",
    Opts = def_opts(#{transport => udp}),
    Q = #dns_query{name = Name, type = ?DNS_TYPE_A},
    Ans = #dns_rr{name = Name, type = ?DNS_TYPE_A, data = #dns_rrdata_a{ip = {1, 2, 3, 4}}},
    Msg = #dns_message{qc = 1, anc = 1, questions = [Q], answers = [Ans]},
    ?assertEqual(Msg, erldns_edns_max_payload_size:call(Msg, Opts)).

udp_replaces_if_below_minimum(_) ->
    Name = ~"example.com",
    Opts = def_opts(#{transport => udp}),
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
    Opts = def_opts(#{transport => udp}),
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
    Opts = def_opts(#{transport => udp}),
    Q = #dns_query{name = Name, type = ?DNS_TYPE_A},
    Ans = #dns_rr{name = Name, type = ?DNS_TYPE_A, data = #dns_rrdata_a{ip = {1, 2, 3, 4}}},
    Ad = #dns_optrr{udp_payload_size = ?MAX_PACKET_SIZE, dnssec = true},
    Msg = #dns_message{
        qc = 1, anc = 1, adc = 1, questions = [Q], answers = [Ans], additional = [Ad]
    },
    ?assertEqual(Msg, erldns_edns_max_payload_size:call(Msg, Opts)).

%%% EDE Tests

ede_extraction(_Config) ->
    %% Test extracting EDE from messages
    EDE1 = #dns_opt_ede{info_code = 6, extra_text = ~"Test 1"},
    EDE2 = #dns_opt_ede{info_code = 22, extra_text = ~"Test 2"},
    OptRR = #dns_optrr{data = [EDE1, EDE2]},
    Msg = #dns_message{id = 2222, adc = 1, additional = [OptRR]},
    EDEs = erldns_edns:get_ede_errors(Msg),
    ?assertEqual([{6, ~"Test 1"}, {22, ~"Test 2"}], lists:sort(EDEs)),
    MsgNoEDE = #dns_message{id = 3333, additional = [#dns_rr{}]},
    ?assertEqual([], erldns_edns:get_ede_errors(MsgNoEDE)).

%% Test that NXDOMAIN does NOT get EDE (it's a valid negative response)
ede_pipeline_nxdomain_no_ede(_Config) ->
    Msg = #dns_message{rc = ?DNS_RCODE_NXDOMAIN},
    Result = erldns_edns_ede:call(Msg, def_opts(#{resolved => true})),
    ?assertEqual([], erldns_edns:get_ede_errors(Result)).

%% Test that NOERROR does NOT get EDE (it's a successful response)
ede_pipeline_noerror_no_ede(_Config) ->
    Msg = #dns_message{rc = ?DNS_RCODE_NOERROR},
    Result = erldns_edns_ede:call(Msg, def_opts(#{resolved => true})),
    ?assertEqual([], erldns_edns:get_ede_errors(Result)).

%% Test that REFUSED with resolved=false gets NOT_AUTHORITATIVE
ede_pipeline_refused(_Config) ->
    Msg = #dns_message{rc = ?DNS_RCODE_REFUSED},
    Result = erldns_edns_ede:call(Msg, def_opts()),
    ?assertMatch([{?DNS_EDE_NOT_AUTHORITATIVE, _}], erldns_edns:get_ede_errors(Result)).

%% Test that SERVFAIL gets OTHER_ERROR by default
ede_pipeline_servfail(_Config) ->
    Msg = #dns_message{rc = ?DNS_RCODE_SERVFAIL},
    Result = erldns_edns_ede:call(Msg, def_opts()),
    ?assertMatch([{?DNS_EDE_OTHER_ERROR, _}], erldns_edns:get_ede_errors(Result)).

%% Test that pipeline creates OPT RR if it doesn't exist
ede_pipeline_creates_optrr(_Config) ->
    Msg = #dns_message{rc = ?DNS_RCODE_REFUSED},
    PreparedOpts = erldns_edns_ede:prepare(def_opts()),
    Result = erldns_edns_ede:call(Msg, PreparedOpts),
    ?assertMatch([#dns_optrr{} | _], Result#dns_message.additional).

%% Test that pipeline appends to existing OPT RR
ede_pipeline_appends_to_optrr(_Config) ->
    ExistingOpt = #dns_optrr{dnssec = true},
    Msg = #dns_message{rc = ?DNS_RCODE_REFUSED, additional = [ExistingOpt]},
    application:set_env(erldns, edns_ede, #{enabled => true, add_text => true}),
    PreparedOpts = erldns_edns_ede:prepare(def_opts()),
    Result = erldns_edns_ede:call(Msg, PreparedOpts),
    %% Should still have one OPT RR, but with EDE added
    [ResultOptRR | _] = Result#dns_message.additional,
    ?assert(ResultOptRR#dns_optrr.dnssec),
    ?assert(length(ResultOptRR#dns_optrr.data) > 0),
    %% Verify EDE is present
    ?assertNotMatch([], erldns_edns:get_ede_errors(Result)).

def_opts() ->
    erldns_pipeline:def_opts().

def_opts(Extra) ->
    maps:merge(def_opts(), Extra).
