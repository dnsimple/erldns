-module(axfr_SUITE).
-compile([export_all, nowarn_export_all]).

-behaviour(ct_suite).

-include_lib("stdlib/include/assert.hrl").
-include_lib("dns_erlang/include/dns.hrl").

-spec all() -> [ct_suite:ct_test_def()].
all() ->
    [{group, all}].

-spec groups() -> [ct_suite:ct_group_def()].
groups() ->
    [{all, [parallel], [has_axfr, has_axfr_no_answers, has_not_axfr]}].

-spec init_per_suite(ct_suite:ct_config()) -> ct_suite:ct_config().
init_per_suite(Config) ->
    Config.

-spec end_per_suite(ct_suite:ct_config()) -> term().
end_per_suite(_) ->
    ok.

%% Tests
has_axfr(_) ->
    Name = <<"example.com">>,
    Opts = maps:merge(def_opts(), #{resolved => true}),
    Q = #dns_query{name = Name, type = ?DNS_TYPE_AXFR},
    A1 = #dns_rr{name = Name, type = ?DNS_TYPE_A, data = #dns_rrdata_a{ip = {1, 2, 3, 4}}},
    A2 = #dns_rr{name = Name, type = ?DNS_TYPE_SOA},
    Msg = #dns_message{qc = 1, anc = 2, questions = [Q], answers = [A1, A2]},
    ?assertMatch(
        #dns_message{anc = 3},
        erldns_axfr:call(Msg, Opts)
    ).

has_axfr_no_answers(_) ->
    Name = <<"example.com">>,
    Opts = maps:merge(def_opts(), #{resolved => true}),
    Q = #dns_query{name = Name, type = ?DNS_TYPE_AXFR},
    Msg = #dns_message{qc = 1, questions = [Q]},
    ?assertMatch(#dns_message{anc = 0}, erldns_axfr:call(Msg, Opts)).

has_not_axfr(_) ->
    Name = <<"example.com">>,
    Opts = maps:merge(def_opts(), #{resolved => true}),
    Q = #dns_query{name = Name, type = ?DNS_TYPE_A},
    A = #dns_rr{name = Name, type = ?DNS_TYPE_A, data = #dns_rrdata_a{ip = {1, 2, 3, 4}}},
    Msg = #dns_message{qc = 1, anc = 1, questions = [Q], answers = [A]},
    ?assertMatch(#dns_message{}, erldns_axfr:call(Msg, Opts)).

def_opts() ->
    erldns_pipeline:def_opts().
