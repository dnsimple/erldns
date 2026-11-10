-module(edns_nsid_SUITE).
-compile([export_all, nowarn_export_all]).

-behaviour(ct_suite).

-include_lib("stdlib/include/assert.hrl").
-include_lib("dns_erlang/include/dns.hrl").

-define(ID, ~"ns1.test").
-define(ZONE, ~"nsid.example").
-define(NAME, ~"www.nsid.example").

-spec all() -> [ct_suite:ct_test_def()].
all() ->
    [
        disabled_without_id,
        id_is_kept_in_opts,
        invalid_id_fails,
        nsid_only_when_asked,
        nsid_ignores_query_data,
        server_id_queries_are_answered,
        other_queries_are_left_alone
    ].

-spec init_per_suite(ct_suite:ct_config()) -> ct_suite:ct_config().
init_per_suite(Config) ->
    application:ensure_all_started([telemetry]),
    Config.

-spec end_per_suite(ct_suite:ct_config()) -> term().
end_per_suite(_) ->
    application:stop(telemetry).

-spec end_per_testcase(ct_suite:ct_testcase(), ct_suite:ct_config()) -> term().
end_per_testcase(_, Config) ->
    application:unset_env(erldns, edns_nsid),
    application:unset_env(erldns, packet_cache),
    erldns_pipeline:delete_pipeline(?MODULE),
    Config.

%% Tests

disabled_without_id(_) ->
    ?assertEqual(disabled, erldns_edns_nsid:prepare(#{})),
    application:set_env(erldns, edns_nsid, #{}),
    ?assertEqual(disabled, erldns_edns_nsid:prepare(#{})).

id_is_kept_in_opts(_) ->
    application:set_env(erldns, edns_nsid, #{id => ?ID}),
    ?assertEqual(#{nsid => ?ID}, erldns_edns_nsid:prepare(#{})).

%% The identifier must fit in one TXT string, and a typo must not go unnoticed.
invalid_id_fails(_) ->
    [
        begin
            application:set_env(erldns, edns_nsid, #{id => Id}),
            ?assertError({invalid_edns_nsid, id, Id}, erldns_edns_nsid:prepare(#{}))
        end
     || Id <- [<<>>, binary:copy(~"a", 256), "ns1.test"]
    ].

%% RFC 5001 §2.2: NSID only goes to the queries that ask for it. Asked for and not, in both orders
%% and repeated, as the packet cache keeps them apart.
nsid_only_when_asked(_) ->
    start(),
    Nsid = [#dns_opt_nsid{data = <<>>}],
    [
        ?assertMatch(
            #dns_message{answers = [_], additional = [#dns_optrr{data = Expected}]},
            resolve(query(?NAME, ?DNS_CLASS_IN, ?DNS_TYPE_A, Options))
        )
     || {Options, Expected} <- [
            {Nsid, [#dns_opt_nsid{data = ?ID}]},
            {[], []},
            {Nsid, [#dns_opt_nsid{data = ?ID}]},
            {[], []}
        ]
    ].

nsid_ignores_query_data(_) ->
    start(),
    Query = query(?NAME, ?DNS_CLASS_IN, ?DNS_TYPE_A, [#dns_opt_nsid{data = ~"ns2"}]),
    ?assertMatch(
        #dns_message{additional = [#dns_optrr{data = [#dns_opt_nsid{data = ?ID}]}]},
        resolve(Query)
    ).

%% RFC 4892: a TXT query of class CH for either name gets the identifier, in any case.
server_id_queries_are_answered(_) ->
    start(),
    [
        ?assertMatch(
            #dns_message{
                qr = true,
                aa = true,
                rc = ?DNS_RCODE_NOERROR,
                anc = 1,
                answers = [
                    #dns_rr{
                        name = Owner,
                        type = ?DNS_TYPE_TXT,
                        class = ?DNS_CLASS_CH,
                        ttl = 0,
                        data = #dns_rrdata_txt{txt = [?ID]}
                    }
                ],
                additional = [#dns_optrr{data = [#dns_opt_nsid{data = ?ID}]}]
            },
            resolve(query(Name, ?DNS_CLASS_CH, ?DNS_TYPE_TXT, [#dns_opt_nsid{data = <<>>}])),
            Name
        )
     || {Name, Owner} <- [
            {~"id.server", ~"id.server"},
            {~"ID.Server", ~"id.server"},
            {~"HOSTNAME.bind", ~"hostname.bind"},
            {~"hostname.bind", ~"hostname.bind"}
        ]
    ].

other_queries_are_left_alone(_) ->
    start(),
    [
        ?assertMatch(
            #dns_message{rc = ?DNS_RCODE_REFUSED, answers = []},
            resolve(query(Name, Class, Type, [])),
            Name
        )
     || {Name, Class, Type} <- [
            {~"id.server", ?DNS_CLASS_IN, ?DNS_TYPE_TXT},
            {~"id.server", ?DNS_CLASS_CH, ?DNS_TYPE_A},
            {~"version.bind", ?DNS_CLASS_CH, ?DNS_TYPE_TXT}
        ]
    ].

%% Helpers

start() ->
    application:set_env(erldns, edns_nsid, #{id => ?ID}),
    application:set_env(erldns, packet_cache, #{}),
    {ok, _} = pg:start_link(erldns),
    {ok, _} = erldns_packet_cache:start_link(),
    erldns_zone_cache:start_link(),
    A = #dns_rr{
        name = ?NAME, type = ?DNS_TYPE_A, ttl = 60, data = #dns_rrdata_a{ip = {192, 0, 2, 1}}
    },
    ok = erldns_zone_cache:put_zone(
        erldns_zone_codec:build_zone(?ZONE, ~"digest", [soa(?ZONE), A], [])
    ),
    erldns_pipeline:store_pipeline(?MODULE, [
        erldns_edns,
        erldns_questions,
        erldns_edns_nsid,
        erldns_packet_cache,
        erldns_resolver,
        erldns_sorter,
        erldns_section_counter,
        erldns_packet_cache
    ]).

resolve(Msg) ->
    erldns_pipeline:call_custom(Msg, #{transport => udp, host => {127, 0, 0, 1}}, ?MODULE).

query(Name, Class, Type, Options) ->
    #dns_message{
        id = 1,
        qc = 1,
        adc = 1,
        questions = [#dns_query{name = Name, class = Class, type = Type}],
        additional = [#dns_optrr{udp_payload_size = 1232, data = Options}]
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
