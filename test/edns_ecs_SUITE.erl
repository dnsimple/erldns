-module(edns_ecs_SUITE).
-compile([export_all, nowarn_export_all]).

-behaviour(ct_suite).

-include_lib("stdlib/include/assert.hrl").
-include_lib("dns_erlang/include/dns.hrl").

-define(ZONE, ~"ecs.example").
-define(NAME, ~"www.ecs.example").

-spec all() -> [ct_suite:ct_test_def()].
all() ->
    [
        prepare_sets_no_client_subnet,
        valid_options_set_client_subnet,
        malformed_options_get_formerr,
        query_without_ecs_is_untouched,
        set_scope_rewrites_the_scope,
        set_scope_without_ecs_does_nothing,
        tailored_answers_are_cached_by_network
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
    application:unset_env(erldns, packet_cache),
    erldns_pipeline:delete_pipeline(?MODULE),
    Config.

%% Tests

prepare_sets_no_client_subnet(_) ->
    ?assertEqual(#{client_subnet => undefined}, erldns_edns_ecs:prepare(#{})).

%% RFC 7871 §7.2.1: the response carries the query's family, source prefix and address back.
valid_options_set_client_subnet(_) ->
    [
        begin
            {Query, Opts} = edns(request([Ecs])),
            {Response, Opts1} = erldns_edns_ecs:call(Query, Opts),
            ?assertEqual(Subnet, maps:get(client_subnet, Opts1), Ecs),
            ?assertMatch(#dns_message{additional = [#dns_optrr{data = [Ecs]}]}, Response, Ecs)
        end
     || {Ecs, Subnet} <- [
            {ecs(1, 24, <<192, 0, 2>>), {{192, 0, 2, 0}, 24}},
            {ecs(1, 32, <<192, 0, 2, 1>>), {{192, 0, 2, 1}, 32}},
            {ecs(1, 0, <<>>), {{0, 0, 0, 0}, 0}},
            {ecs(2, 56, <<16#20, 16#01, 16#0d, 16#b8, 0, 0, 16#ab>>), {
                {16#2001, 16#db8, 0, 16#ab00, 0, 0, 0, 0}, 56
            }}
        ]
    ].

%% RFC 7871 §6 and §7.2.1.
malformed_options_get_formerr(_) ->
    [
        begin
            {Query, Opts} = edns(request([Ecs])),
            ?assertMatch(
                {stop, #dns_message{
                    qr = true,
                    rc = ?DNS_RCODE_FORMERR,
                    anc = 0,
                    auc = 0,
                    adc = 1,
                    questions = [_],
                    additional = [#dns_optrr{data = []}]
                }},
                erldns_edns_ecs:call(Query, Opts),
                Label
            )
        end
     || {Label, Ecs} <- [
            {"unknown family", ecs(3, 24, <<192, 0, 2>>)},
            {"IPv4 prefix too long", ecs(1, 33, <<192, 0, 2, 1, 0>>)},
            {"IPv6 prefix too long", ecs(2, 129, binary:copy(<<0>>, 17))},
            {"address too long", ecs(1, 24, <<192, 0, 2, 0>>)},
            {"address too short", ecs(1, 24, <<192, 0>>)},
            {"bits past the prefix", ecs(1, 23, <<192, 0, 3>>)},
            {"scope in the query", (ecs(1, 24, <<192, 0, 2>>))#dns_opt_ecs{
                scope_prefix_length = 24
            }}
        ]
    ].

query_without_ecs_is_untouched(_) ->
    {Query, Opts} = edns(request([#dns_opt_nsid{data = <<>>}])),
    ?assertEqual(Query, erldns_edns_ecs:call(Query, Opts)).

set_scope_rewrites_the_scope(_) ->
    Ecs = ecs(1, 24, <<192, 0, 2>>),
    Nsid = #dns_opt_nsid{data = ~"ns1"},
    Response = response([Nsid, Ecs]),
    ?assertMatch(
        #dns_message{
            additional = [#dns_optrr{data = [Nsid, #dns_opt_ecs{scope_prefix_length = 20}]}]
        },
        erldns_edns_ecs:set_scope(Response, 20)
    ).

set_scope_without_ecs_does_nothing(_) ->
    [
        ?assertEqual(Msg, erldns_edns_ecs:set_scope(Msg, 24))
     || Msg <- [response([]), (response([]))#dns_message{adc = 0, additional = []}]
    ].

%% A pipe that chooses the answer by network sets the scope, and the packet cache, looking answers
%% up by the query's ECS option, gives each network its own answer.
tailored_answers_are_cached_by_network(_) ->
    start(),
    %% Like the pipes that synthesize answers, it skips cache hits, which have no zone.
    Tailor = fun
        (#dns_message{answers = [A]} = Msg, #{auth_zone := Zone, client_subnet := Subnet}) when
            Zone =/= zone_not_found
        ->
            {{First, _, _, _}, _} = Subnet,
            Tailored = A#dns_rr{data = #dns_rrdata_a{ip = {First, 0, 0, 1}}},
            erldns_edns_ecs:set_scope(Msg#dns_message{answers = [Tailored]}, 8);
        (Msg, _) ->
            Msg
    end,
    erldns_pipeline:store_pipeline(?MODULE, [
        erldns_edns,
        erldns_questions,
        erldns_edns_ecs,
        erldns_packet_cache,
        erldns_resolver,
        Tailor,
        erldns_sorter,
        erldns_section_counter,
        erldns_packet_cache
    ]),
    [
        ?assertMatch(
            #dns_message{
                answers = [#dns_rr{data = #dns_rrdata_a{ip = {First, 0, 0, 1}}}],
                additional = [
                    #dns_optrr{
                        data = [
                            #dns_opt_ecs{
                                source_prefix_length = 24,
                                scope_prefix_length = 8,
                                address = <<First, _, _>>
                            }
                        ]
                    }
                ]
            },
            resolve(request([ecs(1, 24, <<First, 0, 2>>)])),
            First
        )
     || First <- [192, 198, 192, 198]
    ].

%% Helpers

start() ->
    application:set_env(erldns, packet_cache, #{}),
    {ok, _} = pg:start_link(erldns),
    {ok, _} = erldns_packet_cache:start_link(),
    erldns_zone_cache:start_link(),
    A = #dns_rr{
        name = ?NAME, type = ?DNS_TYPE_A, ttl = 60, data = #dns_rrdata_a{ip = {192, 0, 2, 1}}
    },
    ok = erldns_zone_cache:put_zone(
        erldns_zone_codec:build_zone(?ZONE, ~"digest", [soa(?ZONE), A], [])
    ).

resolve(Msg) ->
    erldns_pipeline:call_custom(Msg, #{transport => udp, host => {127, 0, 0, 1}}, ?MODULE).

ecs(Family, Source, Address) ->
    #dns_opt_ecs{
        family = Family, source_prefix_length = Source, scope_prefix_length = 0, address = Address
    }.

%% A query as a listener decodes it, carrying the query's options.
request(Options) ->
    response(Options).

%% A message whose OPT RR carries the response's options.
response(Data) ->
    #dns_message{
        id = 1,
        qc = 1,
        adc = 1,
        questions = [#dns_query{name = ?NAME, type = ?DNS_TYPE_A}],
        additional = [#dns_optrr{udp_payload_size = 1232, data = Data}]
    }.

%% The query and opts as erldns_edns_ecs gets them, after erldns_edns.
edns(Request) ->
    Opts = erldns_edns_ecs:prepare(erldns_edns:prepare(erldns_pipeline:def_opts())),
    case erldns_edns:call(Request, Opts) of
        {Query, Opts1} -> {Query, Opts1};
        Query -> {Query, Opts}
    end.

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
