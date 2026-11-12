-module(edns_SUITE).
-compile([export_all, nowarn_export_all]).

-behaviour(ct_suite).

-define(MAX_PACKET_SIZE, 1232).
-define(WIRE_ZONE, ~"wire.example").
-define(WIRE_NAME, ~"www.wire.example").

-include_lib("stdlib/include/assert.hrl").
-include_lib("dns_erlang/include/dns.hrl").

-spec all() -> [ct_suite:ct_test_def()].
all() ->
    [
        {group, all},
        {group, wire}
    ].

-spec groups() -> [ct_suite:ct_group_def()].
groups() ->
    [
        {all, [parallel], [
            {group, payload_size},
            {group, query_options},
            {group, ede_tests},
            dnssec_extraction
        ]},
        {query_options, [parallel], [
            prepare_sets_no_query_options,
            query_options_move_to_opts,
            query_options_keep_first_of_each_code,
            query_without_optrr_is_untouched,
            optrr_without_options_is_untouched,
            query_records_are_dropped,
            unsupported_version_gets_badvers,
            add_option_to_optrr_anywhere,
            add_option_without_optrr,
            resolver_and_cache_require_edns,
            goes_before_questions,
            every_option_is_keyed_by_its_code,
            unknown_records_are_keyed_by_name,
            update_options_of_the_response
        ]},
        {wire, [], [{group, udp}, {group, tcp}]},
        {udp, [], wire_tests()},
        {tcp, [], wire_tests()},
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
            ede_pipeline_needs_query_optrr,
            ede_pipeline_appends_to_optrr,
            ede_pipeline_optrr_not_first,
            max_payload_size_optrr_not_first
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

%% Queries over the wire, to a node running the pipeline below.
wire_tests() ->
    [
        wire_unknown_options_are_not_sent_back,
        wire_refused_carries_only_ede,
        wire_query_without_edns_gets_no_optrr,
        wire_query_without_question_gets_no_options,
        wire_unsupported_version_gets_badvers
    ].

wire_pipeline() ->
    [
        erldns_edns,
        erldns_questions,
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
    ].

-spec init_per_group(ct_suite:ct_groupname(), ct_suite:ct_config()) -> ct_suite:ct_config().
init_per_group(wire, Config) ->
    Env = [{use_root_hints, false}, {packet_pipeline, wire_pipeline()}],
    app_helper:start_listening(Config, Env, [wire_zone()]);
init_per_group(Transport, Config) when Transport =:= udp; Transport =:= tcp ->
    [{transport, Transport} | Config];
init_per_group(_, Config) ->
    Config.

-spec end_per_group(ct_suite:ct_groupname(), ct_suite:ct_config()) -> term().
end_per_group(wire, Config) ->
    app_helper:stop(Config);
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
    ?assertEqual(Msg, erldns_edns:call(Msg, Opts)).

udp_leaves_additional_empty_if_provided_empty(_) ->
    Name = ~"example.com",
    Opts = def_opts(#{transport => udp}),
    Q = #dns_query{name = Name, type = ?DNS_TYPE_A},
    Ans = #dns_rr{name = Name, type = ?DNS_TYPE_A, data = #dns_rrdata_a{ip = {1, 2, 3, 4}}},
    Msg = #dns_message{qc = 1, anc = 1, questions = [Q], answers = [Ans]},
    ?assertEqual(Msg, erldns_edns:call(Msg, Opts)).

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
        erldns_edns:call(Msg, Opts)
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
        erldns_edns:call(Msg, Opts)
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
    ?assertEqual(Msg, erldns_edns:call(Msg, Opts)).

dnssec_extraction(_Config) ->
    Glue = #dns_rr{name = ~"ns1.example.com", type = ?DNS_TYPE_A},
    Do = #dns_message{additional = [Glue, #dns_optrr{dnssec = true}]},
    NoDo = #dns_message{additional = [Glue, #dns_optrr{}]},
    NoOpt = #dns_message{additional = [Glue]},
    ?assertEqual([{dnssec, true}], erldns_edns:get_opts(Do)),
    ?assertEqual([], erldns_edns:get_opts(NoDo)),
    ?assert(erldns_edns:dnssec_ok(Do)),
    ?assertNot(erldns_edns:dnssec_ok(NoDo)),
    ?assertNot(erldns_edns:dnssec_ok(NoOpt)).

%%% Query options

prepare_sets_no_query_options(_) ->
    ?assertMatch(#{query_edns_options := #{}}, erldns_edns:prepare(def_opts())).

%% RFC 6891 §6.1.2: the query's options are not sent back. The fixed part of the OPT RR is,
%% except for the extended RCODE.
query_options_move_to_opts(_) ->
    Nsid = #dns_opt_nsid{data = <<>>},
    Cookie = #dns_opt_cookie{client = <<1:64>>},
    Unknown = #dns_opt_unknown{id = 65001, bin = <<16#ab, 16#cd>>},
    OptRR = #dns_optrr{
        udp_payload_size = 1232,
        ext_rcode = 1,
        dnssec = true,
        data = [Nsid, Cookie, Unknown]
    },
    {Msg, Opts} = erldns_edns:call(query([OptRR]), edns_opts(udp)),
    ?assertEqual([OptRR#dns_optrr{ext_rcode = 0, data = []}], Msg#dns_message.additional),
    ?assertEqual(
        #{?DNS_EOPTCODE_NSID => Nsid, ?DNS_EOPTCODE_COOKIE => Cookie, 65001 => Unknown},
        maps:get(query_edns_options, Opts)
    ).

query_options_keep_first_of_each_code(_) ->
    First = #dns_opt_cookie{client = <<1:64>>},
    OptRR = #dns_optrr{data = [First, #dns_opt_cookie{client = <<2:64>>}]},
    {_, Opts} = erldns_edns:call(query([OptRR]), edns_opts(tcp)),
    ?assertEqual(#{?DNS_EOPTCODE_COOKIE => First}, maps:get(query_edns_options, Opts)).

query_without_optrr_is_untouched(_) ->
    Msg = query([]),
    ?assertEqual(Msg, erldns_edns:call(Msg, edns_opts(udp))).

optrr_without_options_is_untouched(_) ->
    Msg = query([#dns_optrr{udp_payload_size = 1232, dnssec = true}]),
    ?assertEqual(Msg, erldns_edns:call(Msg, edns_opts(udp))).

%% The response's additional records are its own: only the OPT RR stays, and the header count with
%% it, which pipes that stop the pipeline early rely on.
query_records_are_dropped(_) ->
    OptRR = #dns_optrr{udp_payload_size = 1232},
    ?assertMatch(
        #dns_message{adc = 1, additional = [OptRR]},
        erldns_edns:call(query([glue(), OptRR, glue()]), edns_opts(udp))
    ),
    ?assertMatch(
        #dns_message{adc = 0, additional = []},
        erldns_edns:call(query([glue()]), edns_opts(udp))
    ).

%% RFC 6891 §6.1.3: BADVERS and nothing else, at version 0, the highest this server implements.
unsupported_version_gets_badvers(_) ->
    OptRR = #dns_optrr{
        udp_payload_size = 4096, version = 1, dnssec = true, data = [#dns_opt_nsid{data = <<>>}]
    },
    Query = (query([OptRR]))#dns_message{auc = 1, authority = [glue()]},
    ?assertMatch(
        {stop, #dns_message{
            qr = true,
            rc = ?DNS_RCODE_NOERROR,
            anc = 0,
            auc = 0,
            adc = 1,
            answers = [],
            authority = [],
            additional = [
                #dns_optrr{
                    udp_payload_size = 1232,
                    ext_rcode = ?DNS_ERCODE_BADVERS,
                    version = 0,
                    dnssec = true,
                    data = []
                }
            ]
        }},
        erldns_edns:call(Query, edns_opts(udp))
    ).

add_option_to_optrr_anywhere(_) ->
    Nsid = #dns_opt_nsid{data = ~"ns1"},
    [
        ?assertEqual(
            Expected, (erldns_edns:add_option(query(Additional), Nsid))#dns_message.additional
        )
     || {Additional, Expected} <- [
            {[#dns_optrr{}], [#dns_optrr{data = [Nsid]}]},
            {[glue(), #dns_optrr{}], [glue(), #dns_optrr{data = [Nsid]}]}
        ]
    ].

add_option_without_optrr(_) ->
    Msg = query([glue()]),
    ?assertEqual(Msg, erldns_edns:add_option(Msg, #dns_opt_nsid{data = ~"ns1"})).

%% The resolver answers with the additional section it is given, and the cache looks answers up by
%% it, which is the response's only once erldns_edns has run.
resolver_and_cache_require_edns(_) ->
    [
        ?assertError(
            {badpipe, {unsatisfied_dependency, #{pipe := Pipe, requires := erldns_edns}}},
            erldns_pipeline:store_pipeline(?FUNCTION_NAME, [erldns_questions, Pipe])
        )
     || Pipe <- [erldns_resolver, erldns_packet_cache]
    ].

%% erldns_questions ends the pipeline for a query without a question, which must not skip this pipe.
goes_before_questions(_) ->
    ?assertError(
        {badpipe, {unsatisfied_dependency, #{pipe := erldns_edns, requires := erldns_questions}}},
        erldns_pipeline:store_pipeline(?FUNCTION_NAME, [erldns_questions, erldns_edns])
    ),
    ?assertEqual(ok, erldns_pipeline:store_pipeline(?FUNCTION_NAME, [erldns_edns])),
    erldns_pipeline:delete_pipeline(?FUNCTION_NAME).

every_option_is_keyed_by_its_code(_) ->
    Options = #{
        ?DNS_EOPTCODE_LLQ => #dns_opt_llq{opcode = 1, errorcode = 0, id = 1, leaselife = 60},
        ?DNS_EOPTCODE_UL => #dns_opt_ul{lease = 60},
        ?DNS_EOPTCODE_NSID => #dns_opt_nsid{data = <<>>},
        ?DNS_EOPTCODE_OWNER => #dns_opt_owner{
            primary_mac = <<1:48>>, wakeup_mac = <<>>, password = <<>>
        },
        ?DNS_EOPTCODE_ECS => #dns_opt_ecs{
            family = 1, source_prefix_length = 0, scope_prefix_length = 0, address = <<>>
        },
        ?DNS_EOPTCODE_COOKIE => #dns_opt_cookie{client = <<1:64>>},
        ?DNS_EOPTCODE_EDE => #dns_opt_ede{info_code = 0},
        65001 => #dns_opt_unknown{id = 65001, bin = <<>>}
    },
    OptRR = #dns_optrr{data = maps:values(Options)},
    {_, Opts} = erldns_edns:call(query([OptRR]), edns_opts(tcp)),
    ?assertEqual(Options, maps:get(query_edns_options, Opts)).

%% A record a newer dns_erlang could decode, such as padding, does not crash the pipe.
unknown_records_are_keyed_by_name(_) ->
    Padding = {dns_opt_padding, <<0, 0>>},
    {Msg, Opts} = erldns_edns:call(query([#dns_optrr{data = [Padding]}]), edns_opts(tcp)),
    ?assertMatch(#dns_message{additional = [#dns_optrr{data = []}]}, Msg),
    ?assertEqual(#{dns_opt_padding => Padding}, maps:get(query_edns_options, Opts)).

update_options_of_the_response(_) ->
    Nsid = #dns_opt_nsid{data = ~"ns1"},
    Replace = fun(_) -> [Nsid] end,
    ?assertMatch(
        #dns_message{additional = [_, #dns_optrr{data = [Nsid]}]},
        erldns_edns:update_options(query([glue(), #dns_optrr{data = [Nsid, Nsid]}]), Replace)
    ),
    NoOpt = query([glue()]),
    ?assertEqual(NoOpt, erldns_edns:update_options(NoOpt, Replace)).

query(Additional) ->
    #dns_message{
        qc = 1,
        adc = length(Additional),
        questions = [#dns_query{name = ~"example.com", type = ?DNS_TYPE_A}],
        additional = Additional
    }.

glue() ->
    #dns_rr{
        name = ~"ns.example.com",
        type = ?DNS_TYPE_A,
        ttl = 300,
        data = #dns_rrdata_a{ip = {192, 0, 2, 1}}
    }.

edns_opts(Transport) ->
    erldns_edns:prepare(def_opts(#{transport => Transport})).

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
    Msg = #dns_message{rc = ?DNS_RCODE_NXDOMAIN, additional = [#dns_optrr{}]},
    Result = erldns_edns_ede:call(Msg, def_opts(#{resolved => true})),
    ?assertEqual([], erldns_edns:get_ede_errors(Result)).

%% Test that NOERROR does NOT get EDE (it's a successful response)
ede_pipeline_noerror_no_ede(_Config) ->
    Msg = #dns_message{rc = ?DNS_RCODE_NOERROR, additional = [#dns_optrr{}]},
    Result = erldns_edns_ede:call(Msg, def_opts(#{resolved => true})),
    ?assertEqual([], erldns_edns:get_ede_errors(Result)).

%% Test that REFUSED with resolved=false gets NOT_AUTHORITATIVE
ede_pipeline_refused(_Config) ->
    Msg = #dns_message{rc = ?DNS_RCODE_REFUSED, additional = [#dns_optrr{}]},
    Result = erldns_edns_ede:call(Msg, def_opts()),
    ?assertMatch([{?DNS_EDE_NOT_AUTHORITATIVE, _}], erldns_edns:get_ede_errors(Result)).

%% Test that SERVFAIL gets OTHER_ERROR by default
ede_pipeline_servfail(_Config) ->
    Msg = #dns_message{rc = ?DNS_RCODE_SERVFAIL, additional = [#dns_optrr{}]},
    Result = erldns_edns_ede:call(Msg, def_opts()),
    ?assertMatch([{?DNS_EDE_OTHER_ERROR, _}], erldns_edns:get_ede_errors(Result)).

%% RFC 6891 §7: a query without an OPT RR gets none back, so no EDE either.
ede_pipeline_needs_query_optrr(_Config) ->
    Msg = #dns_message{rc = ?DNS_RCODE_REFUSED},
    PreparedOpts = erldns_edns_ede:prepare(def_opts()),
    ?assertEqual(Msg, erldns_edns_ede:call(Msg, PreparedOpts)).

%% Test that pipeline appends to existing OPT RR
%% RFC6891§6.1.1: an OPT RR "MAY be placed anywhere within the additional data
%% section", and the decoder hands the section back in wire order, so [A, OPT] is
%% what a legal query yields. Matching only the head made the pipe prepend a
%% second OPT RR, giving a response with two of them, which that section forbids.
ede_pipeline_optrr_not_first(_Config) ->
    ARecord = #dns_rr{
        name = ~"ns.example.com",
        type = ?DNS_TYPE_A,
        class = ?DNS_CLASS_IN,
        ttl = 300,
        data = #dns_rrdata_a{ip = {192, 0, 2, 1}}
    },
    application:set_env(erldns, edns_ede, #{enabled => true, add_text => true}),
    PreparedOpts = erldns_edns_ede:prepare(def_opts()),
    [
        begin
            Msg = #dns_message{
                rc = ?DNS_RCODE_REFUSED, adc = length(Additional), additional = Additional
            },
            Result = erldns_edns_ede:call(Msg, PreparedOpts),
            ResultAdditional = Result#dns_message.additional,
            OptRRs = [OptRR || #dns_optrr{} = OptRR <- ResultAdditional],
            %% Exactly one OPT RR, carrying the EDE, and the other records survive
            ?assertMatch([_], OptRRs, Label),
            [#dns_optrr{data = Data}] = OptRRs,
            ?assert(length(Data) > 0, Label),
            ?assertNotMatch([], erldns_edns:get_ede_errors(Result), Label),
            ?assertEqual(
                length([RR || #dns_rr{} = RR <- Additional]),
                length([RR || #dns_rr{} = RR <- ResultAdditional]),
                Label
            )
        end
     || {Label, Additional} <- [
            {"[OPT, A]", [#dns_optrr{dnssec = true}, ARecord]},
            {"[A, OPT]", [ARecord, #dns_optrr{dnssec = true}]},
            {"[A, A, OPT]", [ARecord, ARecord, #dns_optrr{dnssec = true}]}
        ]
    ].

%% Same placement rule: an oversized payload size was left unclamped whenever the
%% OPT RR was not the first additional record, so the response could exceed the
%% fragmentation cap this pipe exists to enforce.
max_payload_size_optrr_not_first(_Config) ->
    ARecord = #dns_rr{
        name = ~"ns.example.com",
        type = ?DNS_TYPE_A,
        class = ?DNS_CLASS_IN,
        ttl = 300,
        data = #dns_rrdata_a{ip = {192, 0, 2, 1}}
    },
    Oversized = #dns_optrr{udp_payload_size = 9999},
    [
        begin
            Msg = #dns_message{
                adc = length(Additional), additional = Additional
            },
            Result = erldns_edns:call(Msg, #{transport => udp}),
            [#dns_optrr{udp_payload_size = Size}] =
                [OptRR || #dns_optrr{} = OptRR <- Result#dns_message.additional],
            ?assertEqual(1232, Size, Label)
        end
     || {Label, Additional} <- [
            {"[OPT, A]", [Oversized, ARecord]},
            {"[A, OPT]", [ARecord, Oversized]},
            {"[A, A, OPT]", [ARecord, ARecord, Oversized]}
        ]
    ],
    %% An in-range size is left alone wherever it sits
    InRange = #dns_optrr{udp_payload_size = 1232},
    Msg2 = #dns_message{adc = 2, additional = [ARecord, InRange]},
    ?assertEqual(
        [InRange],
        (erldns_edns:call(Msg2, #{transport => udp}))#dns_message.additional
    ).

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

%%% Over the wire

%% RFC 6891 §6.1.2
wire_unknown_options_are_not_sent_back(Config) ->
    Options = [
        #dns_opt_unknown{id = 65001, bin = <<16#ab, 16#cd>>}, #dns_opt_cookie{client = <<1:64>>}
    ],
    ?assertMatch(
        #dns_message{
            rc = ?DNS_RCODE_NOERROR,
            answers = [_],
            additional = [#dns_optrr{dnssec = true, data = []}]
        },
        app_helper:exchange(Config, wire_query(?WIRE_NAME, Options, true))
    ).

%% RFC 8914, and the query's unknown option is not sent back with it.
wire_refused_carries_only_ede(Config) ->
    Unknown = #dns_opt_unknown{id = 65001, bin = <<16#ab, 16#cd>>},
    ?assertMatch(
        #dns_message{
            rc = ?DNS_RCODE_REFUSED,
            additional = [
                #dns_optrr{data = [#dns_opt_ede{info_code = ?DNS_EDE_NOT_AUTHORITATIVE}]}
            ]
        },
        app_helper:exchange(Config, wire_query(~"elsewhere.example", [Unknown], false))
    ).

%% RFC 6891 §7: no OPT RR in the query, none in the response, EDE or not.
wire_query_without_edns_gets_no_optrr(Config) ->
    [
        ?assertMatch(
            #dns_message{rc = Rcode, additional = []},
            app_helper:exchange(
                Config, (wire_query(Name, [], false))#dns_message{adc = 0, additional = []}
            ),
            Name
        )
     || {Name, Rcode} <- [
            {?WIRE_NAME, ?DNS_RCODE_NOERROR}, {~"elsewhere.example", ?DNS_RCODE_REFUSED}
        ]
    ].

%% erldns_questions ends the pipeline for a query without a question, after erldns_edns has run.
wire_query_without_question_gets_no_options(Config) ->
    Unknown = #dns_opt_unknown{id = 65001, bin = <<16#ab, 16#cd>>},
    Query = wire_query(?WIRE_NAME, [Unknown], false),
    NoQuestion = Query#dns_message{qc = 0, questions = []},
    ?assertMatch(
        #dns_message{qr = true, qc = 0, adc = 1, additional = [#dns_optrr{data = []}]},
        app_helper:exchange(Config, NoQuestion)
    ).

%% RFC 6891 §6.1.3. dns_erlang won't encode a version above 0, so the query's OPT RR, encoded last
%% and without options, gets its version byte set by hand.
wire_unsupported_version_gets_badvers(Config) ->
    Bin = dns:encode_message(wire_query(?WIRE_NAME, [], false)),
    Head = byte_size(Bin) - 5,
    <<Prefix:Head/binary, 0, Flags:2/binary, 0:16>> = Bin,
    ?assertMatch(
        #dns_message{
            rc = ?DNS_RCODE_NOERROR,
            answers = [],
            additional = [#dns_optrr{version = 0, ext_rcode = ?DNS_ERCODE_BADVERS, data = []}]
        },
        app_helper:exchange(Config, <<Prefix/binary, 1, Flags/binary, 0:16>>)
    ).

wire_query(Name, Options, DnssecOk) ->
    #dns_message{
        id = dns:random_id(),
        qc = 1,
        adc = 1,
        questions = [#dns_query{name = Name, type = ?DNS_TYPE_A}],
        additional = [#dns_optrr{udp_payload_size = 1232, dnssec = DnssecOk, data = Options}]
    }.

wire_zone() ->
    Soa = #dns_rr{
        name = ?WIRE_ZONE,
        type = ?DNS_TYPE_SOA,
        ttl = 3600,
        data = #dns_rrdata_soa{
            mname = <<"ns1.", ?WIRE_ZONE/binary>>,
            rname = <<"admin.", ?WIRE_ZONE/binary>>,
            serial = 1,
            refresh = 3600,
            retry = 600,
            expire = 86400,
            minimum = 300
        }
    },
    A = #dns_rr{
        name = ?WIRE_NAME, type = ?DNS_TYPE_A, ttl = 60, data = #dns_rrdata_a{ip = {192, 0, 2, 1}}
    },
    erldns_zone_codec:build_zone(?WIRE_ZONE, ~"digest", [Soa, A], []).

def_opts() ->
    erldns_pipeline:def_opts().

def_opts(Extra) ->
    maps:merge(def_opts(), Extra).
