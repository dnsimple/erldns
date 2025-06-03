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
""".

-behaviour(supervisor).

-define(DEFAULT_PORT, 53).
-define(DEFAULT_IP, any).

-doc "Name of the listener, a required parameter.".
-type name() :: atom().

-doc "TCP or UDP, or both. Default is `both`".
-type transport() :: tcp | udp | both.

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
- `Protocol` is either `tcp` or `udp`, or `both`. Default is `both`.
""".
-type config() :: #{
    name := name(),
    transport => transport(),
    ip => inet:ip_address() | string() | any,
    port => inet:port_number(),
    parallel_factor => parallel_factor()
}.

-doc """
Statistics about each listener.
""".
-type stats() :: #{
    {name(), tcp | udp} => #{queue_length := non_neg_integer()}
}.
-export_type([name/0, transport/0, parallel_factor/0, config/0, stats/0]).

-export([start_link/0, init/1, get_stats/0]).

-doc false.
-spec start_link() -> supervisor:startlink_ret().
start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, noargs).

-doc false.
-spec init(noargs) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init(noargs) ->
    {ok, {#{strategy => one_for_one}, child_specs()}}.

-doc """
Get statistics about all listeners.
""".
-spec get_stats() -> stats().
get_stats() ->
    Children = supervisor:which_children(?MODULE),
    lists:foldl(fun get_stats/2, #{}, Children).

get_stats({{ranch_embedded_sup, {?MODULE, Name}}, _, _, _}, #{} = Stats) ->
    #{active_connections := ActiveConns} = ranch:info({?MODULE, Name}),
    Stats#{{Name, tcp} => #{queue_length => ActiveConns}};
get_stats({Name, Sup, _, [erldns_proto_udp_sup]}, Stats) ->
    [
        {Pool1, _, _, [wpool]},
        {Pool2, _, _, [wpool]}
    ] = supervisor:which_children(Sup),
    StatsPool1 = wpool:stats(Pool1),
    StatsPool2 = wpool:stats(Pool2),
    {_, TotalPool1} = lists:keyfind(total_message_queue_len, 1, StatsPool1),
    {_, TotalPool2} = lists:keyfind(total_message_queue_len, 1, StatsPool2),
    Stats#{{Name, udp} => #{queue_length => TotalPool1 + TotalPool2}}.

-spec child_specs() -> [supervisor:child_spec()].
child_specs() ->
    Listeners = application:get_env(erldns, listeners, []),
    lists:flatmap(fun child_spec/1, Listeners).

-spec child_spec(config()) -> [supervisor:child_spec()].
child_spec(Config) ->
    Name = get_name(Config),
    Protocol = get_transport(Config),
    Port = get_port(Config),
    IpConfig = get_ip(Config),
    PFactor = get_pfactor(Config),
    child_spec(Name, PFactor, Protocol, [{port, Port} | IpConfig]).

-spec child_spec(name(), parallel_factor(), transport(), [dynamic()]) -> [supervisor:child_spec()].
child_spec(Name, PFactor, tcp, SocketOpts0) ->
    Timeout = erldns_config:ingress_tcp_request_timeout(),
    TcpSocketOpts = tcp_opts(SocketOpts0, Timeout),
    Parallelism = erlang:system_info(schedulers),
    TransOpts = #{
        %% Potentially introduce a cap on the concurrent QPS.
        max_connections => 1024 * PFactor * Parallelism,
        num_acceptors => PFactor * Parallelism,
        num_conns_sups => PFactor * Parallelism,
        num_listen_sockets => Parallelism,
        handshake_timeout => Timeout,
        socket_opts => TcpSocketOpts
    },
    [ranch:child_spec({?MODULE, Name}, ranch_tcp, TransOpts, erldns_proto_tcp, [])];
child_spec(Name, PFactor, udp, SocketOpts) ->
    UdpSocketOpts = udp_opts(SocketOpts),
    [
        #{
            id => Name,
            start => {erldns_proto_udp_sup, start_link, [Name, PFactor, UdpSocketOpts]},
            type => supervisor
        }
    ];
child_spec(Name, PFactor, both, SocketOpts) ->
    [UdpSup] = child_spec(Name, PFactor, udp, SocketOpts),
    [TcpSup] = child_spec(Name, PFactor, tcp, SocketOpts),
    [UdpSup, TcpSup].

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
    case maps:get(transport, Config, both) of
        T when both =:= T; udp =:= T; tcp =:= T ->
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
