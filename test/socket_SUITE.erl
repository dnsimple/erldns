-module(socket_SUITE).
-compile([export_all, nowarn_export_all]).

-behaviour(ct_suite).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include_lib("dns_erlang/include/dns.hrl").

%% Enough acceptors that a platform splitting them by family still has more than
%% one per family to spread across.
-define(PARALLEL_FACTOR, 4).
-define(SENDERS, 64).
-define(PACKETS, 2048).

-spec all() -> [ct_suite:ct_test_def()].
all() ->
    [
        acceptors_cover_every_family,
        acceptor_count_follows_platform,
        stats_are_not_split_by_family,
        udp_load_spreads_as_the_platform_allows,
        udp_and_tcp_answer_queries
    ].

-spec init_per_suite(ct_suite:ct_config()) -> ct_suite:ct_config().
init_per_suite(Config0) ->
    %% A wildcard listener, because that is the default and the only shape a
    %% platform splits by family. All acceptors must also share one port for
    %% traffic to spread between them, which `port => 0' cannot give: each
    %% would bind its own.
    Port = app_helper:reserve_port(),
    AppConfig = [
        {erldns, [
            {listeners, [
                #{
                    name => sockets,
                    transport => standard,
                    port => Port,
                    parallel_factor => ?PARALLEL_FACTOR
                }
            ]}
        ]}
    ],
    [{port, Port} | app_helper:start_per_suite(Config0, AppConfig)].

-spec end_per_suite(ct_suite:ct_config()) -> term().
end_per_suite(Config) ->
    app_helper:stop(Config).

%% Tests

acceptors_cover_every_family(Config) ->
    Wanted = length(erldns_config:split_socket_opts(listener_opts())),
    ?assertEqual(Wanted, length(lists:usort(families(Config)))).

acceptor_count_follows_platform(Config) ->
    Count = length(families(Config)),
    %% Ask for two and see whether this platform is allowed two.
    case erldns_config:socket_count(2) of
        1 -> ?assertEqual(1, Count);
        _ -> ?assert(1 < Count, Count)
    end.

stats_are_not_split_by_family(Config) ->
    %% Splitting a listener per family is an implementation detail; it must not
    %% reach the stats keys.
    Stats = erpc:call(app_helper:get_node(Config), erldns_listeners, get_stats, []),
    ?assertEqual(
        [{sockets, tcp}, {sockets, udp}],
        lists:sort([Key || Key <- maps:keys(Stats), is_tuple(Key)]),
        Stats
    ).

udp_load_spreads_as_the_platform_allows(Config) ->
    %% A dual-stack acceptor receives our IPv4 traffic as a v4-mapped address,
    %% so every acceptor is a candidate unless the platform split them by
    %% family, in which case only the IPv4 half can receive it. A platform
    %% binding a single socket has nothing to spread across at all.
    case candidates(Config) of
        Candidates when Candidates =< 1 ->
            {skip, "a single socket has nothing to spread across"};
        Candidates ->
            Before = recv_counts(Config),
            send_queries(?config(port, Config)),
            timer:sleep(1000),
            After = recv_counts(Config),
            Deltas = deltas(Before, After),
            ct:pal("acceptor receive counts: ~p", [Deltas]),
            Busy = [Socket || {Socket, Delta} <- Deltas, 0 < Delta],
            ?assert([] =/= Busy, "no acceptor received anything"),
            case erldns_config:balances_load() of
                true ->
                    ?assert(
                        1 < length(Busy),
                        lists:flatten(
                            io_lib:format(
                                "expected load spread over ~p sockets, reached ~p",
                                [Candidates, length(Busy)]
                            )
                        )
                    );
                false ->
                    %% Where the kernel does not balance, every packet lands on
                    %% one socket. If that changes, the platform table is stale.
                    ?assertEqual(1, length(Busy), Deltas)
            end
    end.

udp_and_tcp_answer_queries(Config) ->
    %% The platform legs run this suite alone, so it carries the end-to-end
    %% check that a listener on this kernel actually serves: binding sockets
    %% correctly is worth nothing if no answer comes back.
    Port = ?config(port, Config),
    Query = packet(),
    {ok, Udp} = gen_udp:open(0, [inet, binary, {active, false}]),
    ok = gen_udp:send(Udp, {127, 0, 0, 1}, Port, Query),
    {ok, {_, _, UdpReply}} = gen_udp:recv(Udp, 0, 5000),
    ok = gen_udp:close(Udp),
    ?assertMatch(#dns_message{qr = true}, dns:decode_message(UdpReply)),
    {ok, Tcp} = gen_tcp:connect({127, 0, 0, 1}, Port, [inet, binary, {active, false}], 5000),
    ok = gen_tcp:send(Tcp, [<<(byte_size(Query)):16>>, Query]),
    {ok, <<Length:16>>} = gen_tcp:recv(Tcp, 2, 5000),
    {ok, TcpReply} = gen_tcp:recv(Tcp, Length, 5000),
    ok = gen_tcp:close(Tcp),
    ?assertMatch(#dns_message{qr = true}, dns:decode_message(TcpReply)).

%% Helpers

candidates(Config) ->
    Families = families(Config),
    case length(erldns_config:split_socket_opts(listener_opts())) of
        1 -> length(Families);
        _ -> length([Family || Family <- Families, 4 =:= Family])
    end.

listener_opts() ->
    erldns_config:socket_opts([{port, 0}, inet6, {ipv6_v6only, false}, {ip, any}], os:type()).

%% Address family of each acceptor's socket, as the tuple size of its bound
%% address: 4 for IPv4, 8 for IPv6.
families(Config) ->
    erpc:call(app_helper:get_node(Config), fun() ->
        [
            begin
                {ok, {Addr, _}} = inet:sockname(Socket),
                tuple_size(Addr)
            end
         || Socket <- socket_SUITE:acceptor_sockets()
        ]
    end).

recv_counts(Config) ->
    erpc:call(app_helper:get_node(Config), fun() ->
        [
            begin
                {ok, [{recv_cnt, Count}]} = inet:getstat(Socket, [recv_cnt]),
                {Socket, Count}
            end
         || Socket <- socket_SUITE:acceptor_sockets()
        ]
    end).

%% Runs on the peer node, so it must be an exported function rather than a
%% closure over anything local.
acceptor_sockets() ->
    Children = supervisor:which_children(erldns_listeners),
    {_, Sup, _, _} = lists:keyfind({sockets, udp}, 1, Children),
    {_, AccSup, _, _} = lists:keyfind(
        erldns_proto_udp_acceptor_sup, 1, supervisor:which_children(Sup)
    ),
    [
        erldns_proto_udp_acceptor:get_socket(Acceptor)
     || {_, Acceptor, _, _} <- supervisor:which_children(AccSup)
    ].

deltas(Before, After) ->
    [{Socket, Now - Then} || {{Socket, Then}, {_, Now}} <- lists:zip(Before, After)].

%% One source port per sender: a kernel that balances picks the receiving socket
%% by hashing the four-tuple, so a single sender would look exactly like a
%% platform that does not balance at all.
send_queries(Port) ->
    Packet = packet(),
    Senders = [
        begin
            {ok, Socket} = gen_udp:open(0, [inet, binary, {active, false}]),
            Socket
        end
     || _ <- lists:seq(1, ?SENDERS)
    ],
    Ring = list_to_tuple(Senders),
    lists:foreach(
        fun(N) ->
            Sender = element(N rem tuple_size(Ring) + 1, Ring),
            ok = gen_udp:send(Sender, {127, 0, 0, 1}, Port, Packet),
            %% Unthrottled sending overruns the receive buffer, and the loss
            %% would read as skew rather than as loss.
            N rem 128 =:= 0 andalso timer:sleep(1)
        end,
        lists:seq(1, ?PACKETS)
    ),
    [gen_udp:close(Socket) || Socket <- Senders].

packet() ->
    Query = #dns_query{name = ~"example.com", type = ?DNS_TYPE_A},
    dns:encode_message(#dns_message{qc = 1, questions = [Query]}).
