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

-define(DEFAULT_PORT, 53).
-define(DEFAULT_IP, any).

-export([child_specs/0]).

-spec child_specs() -> [supervisor:child_spec()].
child_specs() ->
    Listeners = application:get_env(erldns, listeners, #{}),
    [tcp_child_spec(Name, Config) || Name := #{protocol := tcp} = Config <- Listeners].

tcp_child_spec(Name, Config) ->
    IP = get_ip(Name, Config),
    Port = get_port(Name, Config),
    Timeout = erldns_config:ingress_tcp_request_timeout(),
    SocketOpts = [
        {ip, IP},
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
            any;
        IP when is_tuple(IP), tuple_size(IP) =:= 4 orelse tuple_size(IP) =:= 16 ->
            IP;
        IP when is_list(IP) ->
            case inet:parse_address(IP) of
                {ok, IpAddr} ->
                    IpAddr;
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
