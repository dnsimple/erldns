-module(erldns_listeners).
-moduledoc """
DNS listeners configuration.

In order to configure, add to the application environment:

```erlang
{erldns, [
    {listeners, [
        #{name => Name, transport => Protocol, ip => IP, port => Port, parallel_factor => PFactor}
    ]}
]}
```
See the type `t:config/0` for details.

## Telemetry events

Emits the following telemetry events:

### `[erldns, request, start]`
- Measurements:
```erlang
monotonic_time := integer()
request_size := non_neg_integer()
```
- Metadata:
```erlang
transport := udp | tcp
```

### `[erldns, request, stop]`
- Measurements:
```erlang
monotonic_time := integer()
duration := non_neg_integer()
response_size := non_neg_integer()
```
- Metadata:
```erlang
transport := udp | tcp
dnssec := boolean()
```

### `[erldns, request, error]`
- Measurements:
```erlang
count := non_neg_integer()
```
- Metadata:
```erlang
transport := udp | tcp
kind => exit | error | throw
reason => term()
stacktrace => [term()]
```

### `[erldns, request, timeout]`
- Measurements:
```erlang
count := non_neg_integer()
```
- Metadata:
```erlang
transport := udp | tcp
```

### `[erldns, request, dropped]`
- Measurements:
```erlang
count := non_neg_integer()
```
- Metadata:
```erlang
transport := udp | tcp
```

### `[erldns, request, delayed]`
- Measurements:
```erlang
count := non_neg_integer()
```
- Metadata:
```erlang
transport := udp | tcp
```
""".

-behaviour(supervisor).

-include_lib("kernel/include/logger.hrl").

-define(DEFAULT_TCP_INGRESS_TIMEOUT, 500).
-define(DEFAULT_IDLE_TIMEOUT_MS, 1000).
-define(DEF_MAX_TCP_WORKERS, 50).
-define(DEFAULT_PORT, 53).
-define(DEFAULT_IP, any).

-doc "Name of the listener, a required parameter.".
-type name() :: atom().

-doc "Transport protocol. Default is `standard` which creates both UDP and TCP listeners.".
-type transport() :: udp | tcp | tls | standard.

-doc """
A multiplying factor for parallelisation.

The number of schedulers is multiplied by this factor when creating worker pools.
By default, it is `1`. The number of TCP and UDP acceptors will be of this size,
while the number of UDP workers will be 4x and the maximum number of TCP workers will be 1024x.
Note that the UDP pool is static, while the TCP pool is dynamic.
See `m:wpool` and `m:ranch` respectively for details.
""".
-type parallel_factor() :: 1..512.

-doc """
Configuration map for a listener.

It can contain the following keys:
- `Name` is any desired name in the form of an atom,
- `IP` is `any`, in which case it will listen on all interfaces,
    or a valid ip address in tuple or string format. Default is `any`.
- `Port` is a valid port number. Default is `53`.
- `Transport` is the transport protocol: `udp`, `tcp`, `tls`, or `standard`
    (creates both UDP and TCP). Default is `standard`.
- `Opts` is a map of transport-specific options:
    - For TCP/TLS listeners:
        - `ingress_request_timeout` (optional): Timeout in milliseconds for receiving
          a complete request packet. Defaults to 500ms.
        - `max_concurrent_queries` (optional): Maximum number of parallel request
          workers per connection. Defaults to 50 workers.
        - `idle_timeout_ms` (optional): Timeout in milliseconds for idle connections
          (no data in buffer). Defaults to 1s.
        - `tcp_opts` (optional): List of TCP socket options (e.g., `[{nodelay, true}]`).
          These are passed directly to `gen_tcp` and merged with the default socket options.
    - For TLS listeners (when `transport => tls`):
        - `tls_opts` (required): List of SSL/TLS options as expected by the Erlang `ssl`
          library. These options are appended to the `socket_opts` list and passed to
          `ranch_ssl`. Common options include:
          - `{certfile, Path}` - Path to the server certificate file (required)
          - `{keyfile, Path}` - Path to the private key file (required)
          - `{versions, [tlsv1.2, tlsv1.3]}` - Allowed TLS versions
          - `{alpn_preferred_protocols, [<<"dot">>]}` - ALPN protocols
          - `{reuse_sessions, true}` - Enable session reuse
          - See `m:ssl` module documentation for the complete list of SSL options.
    - For UDP listeners:
        - `udp_opts` (optional): List of UDP socket options (e.g., `[{recbuf, 65536}]`).
          These are passed directly to `gen_udp` and merged with the default socket options.
- `ParallelFactor` is a multiplying factor for parallelisation. Default is `1`.

Example TCP listener:
```erlang
#{
    name => my_tcp_listener,
    transport => tcp,
    port => 8053,
    opts => #{
        ingress_request_timeout => 1000,
        max_concurrent_queries => 100,
        tcp_opts => [{nodelay, true}, {keepalive, true}]
    }
}
```

Example TLS listener:
```erlang
#{
    name => my_tls_listener,
    transport => tls,
    port => 853,
    opts => #{
        ingress_request_timeout => 1000,
        tls_opts => [
            {certfile, "priv/server.crt"},
            {keyfile, "priv/server.key"},
            {versions, ['tlsv1.2', 'tlsv1.3']},
            {alpn_preferred_protocols, [<<"dot">>]},
            {reuse_sessions, true}
        ]
    }
}
```
""".
-type config() :: #{
    name := name(),
    transport => transport(),
    ip => inet:ip_address() | string() | any,
    port => inet:port_number(),
    parallel_factor => parallel_factor(),
    opts => #{atom() => term()}
}.

-doc """
Statistics about each listener.
""".
-type stats() :: #{
    {name(), tcp | udp} => #{queue_length := non_neg_integer()}
}.
-export_type([name/0, transport/0, parallel_factor/0, config/0, stats/0]).

-export([start_link/0, init/1, get_stats/0, reset_queues/0]).

-doc false.
-spec start_link() -> supervisor:startlink_ret().
start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, noargs).

-doc false.
-spec init(noargs) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init(noargs) ->
    {ok, {#{strategy => one_for_one}, child_specs()}}.

-doc "Reset all queues by restarting all listeners.".
-spec reset_queues() -> boolean().
reset_queues() ->
    case supervisor:terminate_child(erldns_sup, ?MODULE) of
        ok ->
            case supervisor:restart_child(erldns_sup, ?MODULE) of
                {ok, _} ->
                    true;
                {error, Reason} ->
                    ?LOG_ERROR(
                        #{what => failed_to_restart_listeners, step => restart, reason => Reason},
                        #{domain => [erldns, listeners]}
                    ),
                    false
            end;
        {error, Reason} ->
            ?LOG_ERROR(
                #{what => failed_to_restart_listeners, step => terminate, reason => Reason},
                #{domain => [erldns, listeners]}
            ),
            false
    end.

-doc "Get statistics about all listeners.".
-spec get_stats() -> stats().
get_stats() ->
    Children = supervisor:which_children(?MODULE),
    lists:foldl(fun get_stats/2, #{}, Children).

get_stats({erldns_sch_mon, _, _, _}, #{} = Stats) ->
    Stats;
get_stats({{ranch_embedded_sup, {?MODULE, {Name, Transport}}}, _, _, _}, #{} = Stats) when
    Transport =:= tcp; Transport =:= tls
->
    #{active_connections := ActiveConns} = ranch:info({?MODULE, {Name, Transport}}),
    Stats#{{Name, Transport} => #{queue_length => ActiveConns}};
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

-spec child_specs() -> [supervisor:child_spec()].
child_specs() ->
    Listeners = application:get_env(erldns, listeners, []),
    SchedMon = #{id => erldns_sch_mon, start => {erldns_sch_mon, start_link, []}, type => worker},
    [SchedMon | lists:flatmap(fun child_spec/1, Listeners)].

-spec child_spec(config()) -> [supervisor:child_spec()].
child_spec(Config) ->
    Name = get_name(Config),
    Transport = get_transport(Config),
    Port = get_port(Config),
    IpConfig = get_ip(Config),
    PFactor = get_pfactor(Config),
    Opts = maps:get(opts, Config, #{}),
    SocketOpts = [{port, Port} | IpConfig],
    case Transport of
        standard ->
            % Expand to both UDP and TCP
            [UdpSup] = child_spec_for_transport(Name, PFactor, udp, SocketOpts, Opts),
            [TcpSup] = child_spec_for_transport(Name, PFactor, tcp, SocketOpts, Opts),
            [UdpSup, TcpSup];
        _ ->
            child_spec_for_transport(Name, PFactor, Transport, SocketOpts, Opts)
    end.

-spec child_spec_for_transport(name(), parallel_factor(), transport(), [dynamic()], map()) ->
    [supervisor:child_spec()].
child_spec_for_transport(Name, PFactor, udp, SocketOpts, Opts) ->
    % Extract UDP-specific socket options from opts if any
    UdpExtraOpts = maps:get(udp_opts, Opts, []),
    UdpSocketOpts = udp_opts(SocketOpts ++ UdpExtraOpts),
    [
        #{
            id => {Name, udp},
            start => {erldns_proto_udp_sup, start_link, [Name, PFactor, UdpSocketOpts]},
            type => supervisor
        }
    ];
child_spec_for_transport(Name, PFactor, tcp, SocketOpts0, Opts) ->
    build_tcp_tls_child_spec(Name, PFactor, tcp, SocketOpts0, Opts, ranch_tcp, undefined);
child_spec_for_transport(Name, PFactor, tls, SocketOpts0, Opts) ->
    % Extract TLS options from opts (required for TLS)
    TlsOpts = maps:get(tls_opts, Opts, undefined),
    case TlsOpts of
        undefined ->
            error({missing_required_option, tls_opts});
        _ when is_list(TlsOpts) ->
            ok
    end,
    build_tcp_tls_child_spec(Name, PFactor, tls, SocketOpts0, Opts, ranch_ssl, TlsOpts).

-spec build_tcp_tls_child_spec(
    name(),
    parallel_factor(),
    tcp | tls,
    [dynamic()],
    map(),
    module(),
    [dynamic()] | undefined
) -> [supervisor:child_spec()].
build_tcp_tls_child_spec(Name, PFactor, Transport, SocketOpts0, Opts, RanchModule, SslOpts) ->
    Timeout = get_tcp_timeout(Opts),
    MaxParallelWorkers = get_tcp_max_parallel_workers(Opts),
    % Extract TCP-specific socket options from opts if any
    TcpExtraOpts = maps:get(tcp_opts, Opts, []),
    TcpSocketOpts = tcp_opts(SocketOpts0 ++ TcpExtraOpts, Timeout),
    % Append SSL options to socket_opts if present
    FinalSocketOpts =
        case SslOpts of
            undefined ->
                TcpSocketOpts;
            _ ->
                TcpSocketOpts ++ SslOpts
        end,
    Parallelism = erlang:system_info(schedulers),
    TransOpts = #{
        alarms => #{
            first_alarm => #{
                type => num_connections,
                threshold => Timeout,
                cooldown => Timeout,
                callback => fun trigger_delayed/4
            }
        },
        max_connections => Timeout,
        num_acceptors => PFactor * Parallelism,
        num_conns_sups => PFactor * Parallelism,
        num_listen_sockets => Parallelism,
        handshake_timeout => Timeout,
        socket_opts => FinalSocketOpts
    },
    IdleTimeout = get_tcp_idle_timeout(Opts),
    ProtoOpts = #{
        ingress_request_timeout => Timeout,
        idle_timeout_ms => IdleTimeout,
        max_concurrent_queries => MaxParallelWorkers
    },
    RanchRef = {?MODULE, {Name, Transport}},
    [ranch:child_spec(RanchRef, RanchModule, TransOpts, erldns_proto_tcp, ProtoOpts)].

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

tcp_opts(SocketOpts0, Timeout) ->
    SocketOpts0 ++
        [
            {send_timeout, Timeout},
            {nodelay, true},
            {keepalive, true},
            {reuseport, true},
            {reuseport_lb, true}
        ].

udp_opts(SocketOpts0) ->
    SocketOpts0 ++
        [
            binary,
            {reuseaddr, true},
            {reuseport, true},
            {reuseport_lb, true},
            {read_packets, 1000},
            {recbuf, 1024 * 1024}
        ].

get_ip(Config) ->
    case maps:get(ip, Config, ?DEFAULT_IP) of
        any ->
            [inet6, {ipv6_v6only, false}, {ip, any}];
        IP when is_tuple(IP), tuple_size(IP) =:= 4 ->
            [inet, {ip, IP}];
        IP when is_tuple(IP), tuple_size(IP) =:= 8 ->
            [inet6, {ip, IP}];
        IP when is_list(IP) ->
            case inet:parse_address(IP) of
                {ok, IpAddr} when is_tuple(IpAddr), tuple_size(IpAddr) =:= 4 ->
                    [inet, {ip, IpAddr}];
                {ok, IpAddr} when is_tuple(IpAddr), tuple_size(IpAddr) =:= 8 ->
                    [inet6, {ip, IpAddr}];
                {error, _} ->
                    error({invalid_listener, ip, Config})
            end;
        _ ->
            error({invalid_listener, ip, Config})
    end.

get_name(#{name := Name}) when is_atom(Name) ->
    Name;
get_name(Config) ->
    error({invalid_listener, name, Config}).

get_port(Config) ->
    case maps:get(port, Config, ?DEFAULT_PORT) of
        Port when is_integer(Port), 0 =< Port, Port =< 65535 ->
            Port;
        _ ->
            error({invalid_listener, port, Config})
    end.

get_transport(Config) ->
    case maps:get(transport, Config, standard) of
        T when T =:= udp; T =:= tcp; T =:= tls; T =:= standard ->
            T;
        _ ->
            error({invalid_listener, transport, Config})
    end.

get_pfactor(Config) ->
    case maps:get(parallel_factor, Config, 1) of
        PFactor when is_integer(PFactor), 0 < PFactor, PFactor =< 512 ->
            PFactor;
        _ ->
            error({invalid_listener, parallel_factor, Config})
    end.

trigger_delayed(_Ref, _Alarm, _SupPid, _ConnPids) ->
    ?LOG_WARNING(
        #{what => tcp_acceptor_delayed, transport => tcp},
        #{domain => [erldns, listeners]}
    ),
    telemetry:execute([erldns, request, delayed], #{count => 1}, #{transport => tcp}).
