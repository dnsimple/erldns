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
          (no data in buffer). Defaults to 2s.
        - `request_timeout_ms` (optional): Timeout in milliseconds for individual
          request processing. If a request exceeds this timeout, it will be killed and
          a SERVFAIL response will be sent to the client. Defaults to 1000ms.
        - `max_connections` (optional): Maximum number of concurrent TCP/TLS connections.
          When this limit is reached, new connections trigger load shedding. Defaults to 1000.
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
        - `ingress_request_timeout` (optional): Timeout in milliseconds for receiving
          a complete request packet. Defaults to 500ms.
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
    {name(), tls | tcp | udp} => #{queue_length := non_neg_integer()}
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
get_stats({{ranch_embedded_sup, {?MODULE, {_, tcp}}}, _, _, _} = Child, Stats) ->
    erldns_proto_tcp_config:get_stats(Child, Stats);
get_stats({{ranch_embedded_sup, {?MODULE, {_, tls}}}, _, _, _} = Child, Stats) ->
    erldns_proto_tcp_config:get_stats(Child, Stats);
get_stats({{_, udp}, _, _, [erldns_proto_udp_sup]} = Child, Stats) ->
    erldns_proto_udp_config:get_stats(Child, Stats).

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
            [UdpSup] = child_spec_for_transport(udp, Name, PFactor, SocketOpts, Opts),
            [TcpSup] = child_spec_for_transport(tcp, Name, PFactor, SocketOpts, Opts),
            [UdpSup, TcpSup];
        _ ->
            child_spec_for_transport(Transport, Name, PFactor, SocketOpts, Opts)
    end.

-spec child_spec_for_transport(transport(), name(), parallel_factor(), [dynamic()], map()) ->
    [supervisor:child_spec()].
child_spec_for_transport(udp, Name, PFactor, SocketOpts, Opts) ->
    erldns_proto_udp_config:child_spec(Name, PFactor, SocketOpts, Opts);
child_spec_for_transport(tcp, Name, PFactor, SocketOpts0, Opts) ->
    erldns_proto_tcp_config:tcp_child_spec(Name, PFactor, SocketOpts0, Opts);
child_spec_for_transport(tls, Name, PFactor, SocketOpts0, Opts) ->
    erldns_proto_tcp_config:tls_child_spec(Name, PFactor, SocketOpts0, Opts).

-spec get_ip(config()) -> list().
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

-spec get_name(config()) -> name().
get_name(#{name := Name}) when is_atom(Name) ->
    Name;
get_name(Config) ->
    error({invalid_listener, name, Config}).

-spec get_port(config()) -> inet:port_number().
get_port(Config) ->
    case maps:get(port, Config, ?DEFAULT_PORT) of
        Port when is_integer(Port), 0 =< Port, Port =< 65535 ->
            Port;
        _ ->
            error({invalid_listener, port, Config})
    end.

-spec get_transport(config()) -> transport().
get_transport(Config) ->
    case maps:get(transport, Config, standard) of
        T when T =:= udp; T =:= tcp; T =:= tls; T =:= standard ->
            T;
        _ ->
            error({invalid_listener, transport, Config})
    end.

-spec get_pfactor(config()) -> pos_integer().
get_pfactor(Config) ->
    case maps:get(parallel_factor, Config, 1) of
        PFactor when is_integer(PFactor), 0 < PFactor, PFactor =< 512 ->
            PFactor;
        _ ->
            error({invalid_listener, parallel_factor, Config})
    end.
