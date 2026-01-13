-module(erldns_proto_tcp_config).
-moduledoc false.

-include_lib("kernel/include/logger.hrl").

-export([tcp_child_spec/4, tls_child_spec/4, get_stats/2]).

-type socket_option() ::
    gen_tcp:option()
    | inet:address_family()
    | {ip, inet:ip_address()}
    | {port, inet:port_number()}.
-export_type([socket_option/0]).

-define(DEFAULT_TCP_INGRESS_TIMEOUT, 1000).
-define(DEFAULT_IDLE_TIMEOUT_MS, 2000).
-define(DEFAULT_REQUEST_TIMEOUT_MS, 1000).
-define(DEFAULT_MAX_CONNECTIONS, 1000).
-define(DEF_MAX_TCP_WORKERS, 50).

-spec get_stats(dynamic(), erldns_listeners:stats()) -> erldns_listeners:stats().
get_stats({{ranch_embedded_sup, {erldns_listeners, {Name, Transport}}}, _, _, _}, Stats) ->
    #{active_connections := ActiveConns} = ranch:info({erldns_listeners, {Name, Transport}}),
    Stats#{{Name, Transport} => #{queue_length => ActiveConns}}.

-spec tcp_child_spec(
    erldns_listeners:name(),
    erldns_listeners:parallel_factor(),
    [socket_option()],
    map()
) -> [supervisor:child_spec()].
tcp_child_spec(Name, PFactor, SocketOpts, Opts) ->
    RanchRef = ranch_ref(Name, tcp),
    RanchMod = ranch_module(tcp),
    child_spec(PFactor, SocketOpts, Opts, RanchRef, RanchMod, []).

-spec tls_child_spec(
    erldns_listeners:name(),
    erldns_listeners:parallel_factor(),
    [socket_option()],
    map()
) -> [supervisor:child_spec()].
tls_child_spec(Name, PFactor, SocketOpts, Opts) ->
    RanchRef = ranch_ref(Name, tls),
    RanchMod = ranch_module(tls),
    SslOpts = get_tls_opts(Opts),
    child_spec(PFactor, SocketOpts, Opts, RanchRef, RanchMod, SslOpts).

child_spec(PFactor, SocketOpts, Opts, RanchRef, RanchMod, SslOpts) ->
    Parallelism = erlang:system_info(schedulers),
    Timeout = get_tcp_timeout(Opts),
    MaxConnections = get_tcp_max_connections(Opts),
    % Extract TCP-specific socket options from opts if any
    TcpExtraOpts = maps:get(tcp_opts, Opts, []),
    TcpSocketOpts = tcp_opts(SocketOpts ++ TcpExtraOpts, Timeout),
    % Append SSL options to socket_opts if present
    FinalSocketOpts = TcpSocketOpts ++ SslOpts,
    TransOpts = #{
        alarms => #{
            first_alarm => #{
                type => num_connections,
                threshold => MaxConnections,
                cooldown => Timeout,
                callback => fun trigger_delayed/4
            }
        },
        max_connections => MaxConnections,
        num_acceptors => PFactor * Parallelism,
        num_conns_sups => PFactor * Parallelism,
        num_listen_sockets => Parallelism,
        handshake_timeout => Timeout,
        socket_opts => FinalSocketOpts
    },
    ProtoOpts = #{
        ingress_request_timeout => Timeout,
        idle_timeout_ms => get_tcp_idle_timeout(Opts),
        max_concurrent_queries => get_tcp_max_parallel_workers(Opts),
        request_timeout_ms => get_tcp_request_timeout(Opts)
    },
    [ranch:child_spec(RanchRef, RanchMod, TransOpts, erldns_proto_tcp, ProtoOpts)].

% Extract TLS options from opts (required for TLS)
get_tls_opts(Opts) ->
    TlsOpts = maps:get(tls_opts, Opts, undefined),
    case TlsOpts of
        undefined ->
            error({missing_required_option, tls_opts});
        _ when is_list(TlsOpts) ->
            TlsOpts
    end.

ranch_module(tcp) ->
    ranch_tcp;
ranch_module(tls) ->
    ranch_ssl.

ranch_ref(Name, Transport) ->
    {erldns_listeners, {Name, Transport}}.

-spec get_tcp_timeout(map()) -> non_neg_integer().
get_tcp_timeout(ListenerOpts) ->
    case maps:get(ingress_request_timeout, ListenerOpts, ?DEFAULT_TCP_INGRESS_TIMEOUT) of
        Timeout when is_integer(Timeout), Timeout > 0 ->
            Timeout;
        Invalid ->
            error({invalid_option, ingress_request_timeout, Invalid})
    end.

-spec get_tcp_max_parallel_workers(map()) -> non_neg_integer().
get_tcp_max_parallel_workers(ListenerOpts) ->
    case maps:get(max_concurrent_queries, ListenerOpts, ?DEF_MAX_TCP_WORKERS) of
        Max when is_integer(Max), Max > 0 ->
            Max;
        _ ->
            ?DEF_MAX_TCP_WORKERS
    end.

-spec get_tcp_idle_timeout(map()) -> non_neg_integer().
get_tcp_idle_timeout(ListenerOpts) ->
    case maps:get(idle_timeout_ms, ListenerOpts, ?DEFAULT_IDLE_TIMEOUT_MS) of
        Timeout when is_integer(Timeout), Timeout > 0 ->
            Timeout;
        _ ->
            ?DEFAULT_IDLE_TIMEOUT_MS
    end.

-spec get_tcp_request_timeout(map()) -> non_neg_integer() | infinity.
get_tcp_request_timeout(ListenerOpts) ->
    case maps:get(request_timeout_ms, ListenerOpts, ?DEFAULT_REQUEST_TIMEOUT_MS) of
        Timeout when infinity =:= Timeout orelse (is_integer(Timeout) andalso Timeout > 0) ->
            Timeout;
        Invalid ->
            error({invalid_option, request_timeout_ms, Invalid})
    end.

-spec get_tcp_max_connections(map()) -> non_neg_integer().
get_tcp_max_connections(ListenerOpts) ->
    case maps:get(max_connections, ListenerOpts, ?DEFAULT_MAX_CONNECTIONS) of
        Max when is_integer(Max), Max > 0 ->
            Max;
        Invalid ->
            error({invalid_option, max_connections, Invalid})
    end.

-spec tcp_opts([socket_option()], non_neg_integer()) -> [socket_option()].
tcp_opts(SocketOpts, Timeout) ->
    SocketOpts ++
        [
            {send_timeout, Timeout},
            {nodelay, true},
            {keepalive, true},
            {reuseport, true},
            {reuseport_lb, true}
        ].

-spec trigger_delayed(term(), term(), term(), term()) -> ok.
trigger_delayed(_Ref, _Alarm, _SupPid, _ConnPids) ->
    ?LOG_WARNING(
        #{what => tcp_acceptor_delayed, transport => tcp},
        #{domain => [erldns, listeners]}
    ),
    telemetry:execute([erldns, request, delayed], #{count => 1}, #{transport => tcp}).
