-module(erldns_proto_udp_config).
-moduledoc false.

-define(DEFAULT_UDP_INGRESS_TIMEOUT, 500).

-export([child_spec/4, get_stats/2]).

-spec get_stats(dynamic(), erldns_listeners:stats()) -> erldns_listeners:stats().
get_stats({{Name, udp}, Sup, _, [erldns_proto_udp_sup]}, Stats) ->
    [
        {_, AccSup, _, [erldns_proto_udp_acceptor_sup]},
        {Pool2, _, _, [wpool]}
    ] = supervisor:which_children(Sup),
    TotalPool1 = lists:foldl(
        fun({_, Worker, _, _}, Acc) ->
            {_, Count} = erlang:process_info(Worker, message_queue_len),
            Acc + Count
        end,
        0,
        supervisor:which_children(AccSup)
    ),
    StatsPool = wpool:stats(Pool2),
    {_, TotalPool2} = lists:keyfind(total_message_queue_len, 1, StatsPool),
    Stats#{{Name, udp} => #{queue_length => TotalPool1 + TotalPool2}}.

-spec child_spec(
    erldns_listeners:name(),
    erldns_listeners:parallel_factor(),
    [gen_udp:option()],
    map()
) -> [supervisor:child_spec()].
child_spec(Name, PFactor, SocketOpts, Opts) ->
    UdpExtraOpts = maps:get(udp_opts, Opts, []),
    UdpSocketOpts = SocketOpts ++ base_udp_opts() ++ UdpExtraOpts,
    Timeout = get_udp_timeout(Opts),
    [
        #{
            id => {Name, udp},
            start => {erldns_proto_udp_sup, start_link, [Name, PFactor, Timeout, UdpSocketOpts]},
            type => supervisor
        }
    ].

-spec get_udp_timeout(map()) -> non_neg_integer().
get_udp_timeout(ListenerOpts) ->
    case maps:get(ingress_request_timeout, ListenerOpts, ?DEFAULT_UDP_INGRESS_TIMEOUT) of
        Timeout when is_integer(Timeout), Timeout > 0 ->
            Timeout;
        Invalid ->
            error({invalid_option, ingress_request_timeout, Invalid})
    end.

-spec base_udp_opts() -> [gen_udp:option()].
base_udp_opts() ->
    [
        binary,
        {reuseaddr, true},
        {reuseport, true},
        {reuseport_lb, true},
        {read_packets, 1000},
        {recbuf, 1024 * 1024}
    ].
