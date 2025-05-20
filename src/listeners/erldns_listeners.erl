-module(erldns_listeners).
-moduledoc """
DNS listeners configuration.

At the moment it supports only TCP.

In order to configure, add to the application environment:

```erlang
{erldns, [
    {listeners, #{
        Name => #{protocol => tcp, ip => IP, port => Port}
    }}
]}
```
where `Name` is any desired name,
`IP` is `any` or a valid ip address in tuple or string format,
and `Port` is a valid port.
""".

-behaviour(supervisor).

-define(DEFAULT_PORT, 53).
-define(DEFAULT_IP, any).

-export([start_link/0, init/1]).

-spec start_link() -> supervisor:startlink_ret().
start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, noargs).

-spec init(noargs) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init(noargs) ->
    {ok, {#{strategy => one_for_one}, child_specs()}}.

-spec child_specs() -> [supervisor:child_spec()].
child_specs() ->
    Listeners = application:get_env(erldns, listeners, #{}),
    [tcp_child_spec(Name, Config) || Name := #{protocol := tcp} = Config <- Listeners].

tcp_child_spec(Name, Config) ->
    IpConfig = get_ip(Name, Config),
    Port = get_port(Name, Config),
    Timeout = erldns_config:ingress_tcp_request_timeout(),
    SocketOpts =
        IpConfig ++
            [
                {nodelay, true},
                {port, Port},
                {send_timeout, Timeout},
                {keepalive, true},
                {reuseport, true},
                {reuseport_lb, true}
            ],
    Parallelism = erlang:system_info(schedulers),
    TransOpts = #{
        %% Potentially introduce a cap on the concurrent QPS.
        max_connections => infinity,
        num_acceptors => Parallelism,
        num_conns_sups => Parallelism,
        num_listen_sockets => Parallelism,
        socket_opts => SocketOpts
    },
    ProtoOpts = [],
    ranch:child_spec({?MODULE, Name}, ranch_tcp, TransOpts, erldns_tcp_proto, ProtoOpts).

get_ip(Name, Config) ->
    case maps:get(ip, Config, ?DEFAULT_IP) of
        any ->
            [inet6, {ipv6_v6only, false}, {ip, any}];
        IP when is_tuple(IP), tuple_size(IP) =:= 4 ->
            [inet, {ip, IP}];
        IP when is_tuple(IP), tuple_size(IP) =:= 8 ->
            [inet6, {ipv6_v6only, false}, {ip, IP}];
        IP when is_list(IP) ->
            case inet:parse_address(IP) of
                {ok, IpAddr} when is_tuple(IpAddr), tuple_size(IpAddr) =:= 4 ->
                    [inet, {ip, IpAddr}];
                {ok, IpAddr} when is_tuple(IpAddr), tuple_size(IpAddr) =:= 8 ->
                    [inet6, {ipv6_v6only, false}, {ip, IpAddr}];
                {error, _} ->
                    error({invalid_listener_ip, Name, Config})
            end
    end.

get_port(Name, Config) ->
    case maps:get(port, Config, ?DEFAULT_PORT) of
        Port when is_integer(Port), 0 =< Port, Port =< 65535 ->
            Port;
        _ ->
            error({invalid_listener_port, Name, Config})
    end.
