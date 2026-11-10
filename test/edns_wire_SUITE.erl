-module(edns_wire_SUITE).
-compile([export_all, nowarn_export_all]).

-behaviour(ct_suite).

-include_lib("stdlib/include/assert.hrl").
-include_lib("dns_erlang/include/dns.hrl").

-define(ID, ~"ns1.test").
-define(ZONE, ~"wire.example").
-define(NAME, ~"www.wire.example").

-spec all() -> [ct_suite:ct_test_def()].
all() ->
    [{group, udp}, {group, tcp}].

-spec groups() -> [ct_suite:ct_group_def()].
groups() ->
    Tests = [
        unknown_options_are_not_sent_back,
        nsid_only_when_asked,
        server_id_queries_are_answered,
        ecs_is_sent_back,
        malformed_ecs_gets_formerr,
        refused_carries_only_ede,
        query_without_edns_gets_no_optrr
    ],
    [{udp, [sequence], Tests}, {tcp, [sequence], Tests}].

-spec init_per_suite(ct_suite:ct_config()) -> ct_suite:ct_config().
init_per_suite(Config0) ->
    %% UDP and TCP must land on the same port, which `port => 0' would not give.
    Port = app_helper:reserve_port(),
    AppConfig = [
        {erldns, [
            {listeners, [#{name => inet_1, ip => {127, 0, 0, 1}, port => Port}]},
            {use_root_hints, false},
            {edns_nsid, #{id => ?ID}},
            {packet_pipeline, [
                erldns_edns,
                erldns_questions,
                erldns_edns_nsid,
                erldns_edns_ecs,
                erldns_query_throttle,
                erldns_packet_cache,
                erldns_resolver_recursive,
                erldns_resolver,
                erldns_dnssec,
                erldns_edns_ede,
                erldns_sorter,
                erldns_section_counter,
                erldns_packet_cache,
                erldns_empty_verification
            ]}
        ]}
    ],
    Config = app_helper:start_per_suite(Config0, AppConfig),
    A = #dns_rr{
        name = ?NAME, type = ?DNS_TYPE_A, ttl = 60, data = #dns_rrdata_a{ip = {192, 0, 2, 1}}
    },
    Zone = erldns_zone_codec:build_zone(?ZONE, ~"digest", [soa(?ZONE), A], []),
    ok = erpc:call(app_helper:get_node(Config), erldns_zone_cache, put_zone, [Zone]),
    [{port, Port} | Config].

-spec end_per_suite(ct_suite:ct_config()) -> term().
end_per_suite(Config) ->
    app_helper:stop(Config).

-spec init_per_group(ct_suite:ct_groupname(), ct_suite:ct_config()) -> ct_suite:ct_config().
init_per_group(Transport, Config) ->
    [{transport, Transport} | Config].

-spec end_per_group(ct_suite:ct_groupname(), ct_suite:ct_config()) -> term().
end_per_group(_, _) ->
    ok.

%% Tests

%% RFC 6891 §6.1.2
unknown_options_are_not_sent_back(Config) ->
    Unknown = #dns_opt_unknown{id = 65001, bin = <<16#ab, 16#cd>>},
    Cookie = #dns_opt_cookie{client = <<1:64>>},
    ?assertMatch(
        #dns_message{
            rc = ?DNS_RCODE_NOERROR,
            answers = [_],
            additional = [#dns_optrr{dnssec = true, data = []}]
        },
        exchange(Config, query(?NAME, [Unknown, Cookie], true))
    ).

%% RFC 5001 §2.2, through the packet cache.
nsid_only_when_asked(Config) ->
    Nsid = #dns_opt_nsid{data = <<>>},
    [
        ?assertMatch(
            #dns_message{answers = [_], additional = [#dns_optrr{data = Expected}]},
            exchange(Config, query(?NAME, Options))
        )
     || {Options, Expected} <- [
            {[Nsid], [#dns_opt_nsid{data = ?ID}]},
            {[], []},
            {[Nsid], [#dns_opt_nsid{data = ?ID}]}
        ]
    ].

%% RFC 4892
server_id_queries_are_answered(Config) ->
    [
        ?assertMatch(
            #dns_message{
                aa = true,
                rc = ?DNS_RCODE_NOERROR,
                answers = [
                    #dns_rr{
                        class = ?DNS_CLASS_CH,
                        type = ?DNS_TYPE_TXT,
                        data = #dns_rrdata_txt{txt = [?ID]}
                    }
                ]
            },
            exchange(Config, (query(Name, []))#dns_message{
                questions = [#dns_query{name = Name, class = ?DNS_CLASS_CH, type = ?DNS_TYPE_TXT}]
            }),
            Name
        )
     || Name <- [~"id.server", ~"hostname.bind"]
    ].

%% RFC 7871 §7.2.1
ecs_is_sent_back(Config) ->
    Ecs = #dns_opt_ecs{
        family = 1, source_prefix_length = 24, scope_prefix_length = 0, address = <<192, 0, 2>>
    },
    ?assertMatch(
        #dns_message{answers = [_], additional = [#dns_optrr{data = [Ecs]}]},
        exchange(Config, query(?NAME, [Ecs]))
    ).

%% RFC 7871 §6: bits set past the source prefix.
malformed_ecs_gets_formerr(Config) ->
    Ecs = #dns_opt_ecs{
        family = 1, source_prefix_length = 24, scope_prefix_length = 0, address = <<192, 0, 2, 1>>
    },
    ?assertMatch(
        #dns_message{rc = ?DNS_RCODE_FORMERR, answers = [], additional = [#dns_optrr{data = []}]},
        exchange(Config, query(?NAME, [Ecs]))
    ).

%% RFC 8914, and the query's unknown option is not sent back with it.
refused_carries_only_ede(Config) ->
    Unknown = #dns_opt_unknown{id = 65001, bin = <<16#ab, 16#cd>>},
    ?assertMatch(
        #dns_message{
            rc = ?DNS_RCODE_REFUSED,
            additional = [
                #dns_optrr{data = [#dns_opt_ede{info_code = ?DNS_EDE_NOT_AUTHORITATIVE}]}
            ]
        },
        exchange(Config, query(~"elsewhere.example", [Unknown]))
    ).

%% RFC 6891 §7: no OPT RR in the query, none in the response, EDE or not.
query_without_edns_gets_no_optrr(Config) ->
    [
        ?assertMatch(
            #dns_message{rc = Rcode, additional = []},
            exchange(Config, (query(Name, []))#dns_message{adc = 0, additional = []}),
            Name
        )
     || {Name, Rcode} <- [{?NAME, ?DNS_RCODE_NOERROR}, {~"elsewhere.example", ?DNS_RCODE_REFUSED}]
    ].

%% Helpers

exchange(Config, Query) ->
    Port = proplists:get_value(port, Config),
    Bin = dns:encode_message(Query),
    Response =
        case proplists:get_value(transport, Config) of
            udp ->
                {ok, Socket} = gen_udp:open(0, [binary, {active, false}]),
                ok = gen_udp:send(Socket, {127, 0, 0, 1}, Port, Bin),
                {ok, {_, _, Packet}} = gen_udp:recv(Socket, 0, 5000),
                ok = gen_udp:close(Socket),
                Packet;
            tcp ->
                Opts = [binary, {active, false}, {packet, 2}],
                {ok, Socket} = gen_tcp:connect({127, 0, 0, 1}, Port, Opts, 5000),
                ok = gen_tcp:send(Socket, Bin),
                {ok, Packet} = gen_tcp:recv(Socket, 0, 5000),
                ok = gen_tcp:close(Socket),
                Packet
        end,
    #dns_message{id = Id} = Decoded = dns:decode_message(Response),
    ?assertEqual(Query#dns_message.id, Id),
    Decoded.

query(Name, Options) ->
    query(Name, Options, false).

query(Name, Options, DnssecOk) ->
    #dns_message{
        id = dns:random_id(),
        qc = 1,
        adc = 1,
        questions = [#dns_query{name = Name, type = ?DNS_TYPE_A}],
        additional = [#dns_optrr{udp_payload_size = 1232, dnssec = DnssecOk, data = Options}]
    }.

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
