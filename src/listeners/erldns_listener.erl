-module(erldns_listener).

-export([start/0]).

start() ->
    ets:new(?MODULE, [public, named_table, {read_concurrency, true}, {write_concurrency, auto}]),
    prometheus_quantile_summary:declare([{name, udp_query_microseconds}, {unit, seconds}, {help, ""}]),
    supervisor:start_child(erldns_sup, new_tcp_server()),
    supervisor:start_child(erldns_sup, new_udp_server()).

new_tcp_server() ->
    %% Integrate natively with the OS's SO_REUSEPORT and SO_REUSEPORT_LB
    %% for both Linux and BSD systems
    SocketOpts = [
        inet,
        {ip, {0, 0, 0, 0}},
        {port, 9999},
        {keepalive, true},
        {reuseport, true},
        {reuseport_lb, true}
    ],
    Parallelism = erlang:system_info(schedulers),
    TransOpts = #{
        %% Potentially introduce a cap on the concurrent QPS.
        max_connections => infinity,
        %% Automatically make the acceptor pool as big as the available resources
        num_acceptors => Parallelism,
        num_conns_sups => Parallelism,
        num_listen_sockets => Parallelism,
        socket_opts => SocketOpts
    },
    ProtoOpts = [],
    %% Use [ranch](https://hex.pm/packages/ranch) for socket management
    %% This is one of the most popular libraries for both Erlang and Elixir,
    %% one of the best maintained and most carefully optimised.
    ranch:child_spec(?MODULE, ranch_tcp, TransOpts, proto_tcp_server, ProtoOpts).

new_udp_server() ->
    #{id => new_udp_server, start => {proto_udp_sup, start_link, []}, type => supervisor}.
