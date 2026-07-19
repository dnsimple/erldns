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
get_stats({{ranch_embedded_sup, {erldns_listeners, Ref}}, _, _, _}, Stats) ->
    #{active_connections := ActiveConns} = ranch:info({erldns_listeners, Ref}),
    Key = {element(1, Ref), element(2, Ref)},
    maps:update_with(
        Key,
        fun(#{queue_length := Queued}) -> #{queue_length => Queued + ActiveConns} end,
        #{queue_length => ActiveConns},
        Stats
    ).

-spec tcp_child_spec(
    erldns_listeners:name(),
    erldns_listeners:parallel_factor(),
    [socket_option()],
    map()
) -> [supervisor:child_spec()].
tcp_child_spec(Name, PFactor, SocketOpts, Opts) ->
    child_specs(Name, tcp, PFactor, SocketOpts, Opts, []).

-spec tls_child_spec(
    erldns_listeners:name(),
    erldns_listeners:parallel_factor(),
    [socket_option()],
    map()
) -> [supervisor:child_spec()].
tls_child_spec(Name, PFactor, SocketOpts, Opts) ->
    child_specs(Name, tls, PFactor, SocketOpts, Opts, get_tls_opts(Opts)).

%% One ranch listener per socket family the platform needs bound separately.
%% The parallelism knobs are shared out between them, so the total number of
%% acceptors and listen sockets stays what the parallel factor asked for.
child_specs(Name, Transport, PFactor, SocketOpts, Opts, SslOpts) ->
    Variants = erldns_config:split_socket_opts(SocketOpts),
    RanchMod = ranch_module(Transport),
    Share = length(Variants),
    lists:append([
        child_spec(
            PFactor, Variant, Opts, ranch_ref(Name, Transport, Index), RanchMod, SslOpts, Share
        )
     || {Index, Variant} <- lists:enumerate(Variants)
    ]).

child_spec(PFactor, SocketOpts, Opts, RanchRef, RanchMod, SslOpts, Share) ->
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
        num_acceptors => share(PFactor * Parallelism, Share),
        num_conns_sups => share(PFactor * Parallelism, Share),
        num_listen_sockets => share(erldns_config:socket_count(Parallelism), Share),
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

%% The first listener keeps the unqualified ref, so a platform that binds one
%% socket is addressed exactly as before.
ranch_ref(Name, Transport, 1) ->
    {erldns_listeners, {Name, Transport}};
ranch_ref(Name, Transport, Index) ->
    {erldns_listeners, {Name, Transport, Index}}.

-spec share(pos_integer(), pos_integer()) -> pos_integer().
share(Wanted, Among) ->
    max(1, Wanted div Among).

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
            {keepalive, true}
        ].

-spec trigger_delayed(term(), term(), term(), term()) -> ok.
trigger_delayed(_Ref, _Alarm, _SupPid, _ConnPids) ->
    ?LOG_WARNING(
        #{what => tcp_acceptor_delayed, transport => tcp},
        #{domain => [erldns, listeners]}
    ),
    telemetry:execute([erldns, request, delayed], #{count => 1}, #{transport => tcp}).
