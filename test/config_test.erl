-module(config_test).

-include_lib("eunit/include/eunit.hrl").

-define(DEFAULT_IPV4_ADDRESS, {127, 0, 0, 1}).
-define(DEFAULT_IPV6_ADDRESS, {0, 0, 0, 0, 0, 0, 0, 1}).
-define(DEFAULT_PORT, 53).

get_servers_undefined_test() ->
    ?assertEqual(
        [
            [{name, inet}, {address, ?DEFAULT_IPV4_ADDRESS}, {port, ?DEFAULT_PORT}, {family, inet}],
            [{name, inet6}, {address, ?DEFAULT_IPV6_ADDRESS}, {port, ?DEFAULT_PORT}, {family, inet6}]
        ],
        erldns_config:get_servers()
    ).

get_servers_empty_list_test() ->
    application:set_env(erldns, servers, []),
    ?assertEqual([], erldns_config:get_servers()).

get_servers_single_server_test() ->
    application:set_env(erldns, servers, [[{name, example}, {address, "127.0.0.1"}, {port, 8053}, {family, inet}]]),
    ?assertEqual(
        [[{name, example}, {address, {127, 0, 0, 1}}, {port, 8053}, {family, inet}, {processes, 1}, {with_tcp, true}]],
        erldns_config:get_servers()
    ).

get_servers_multiple_servers_test() ->
    application:set_env(
        erldns,
        servers,
        [
            [{name, example_inet}, {address, "127.0.0.1"}, {port, 8053}, {family, inet}],
            [{name, example_inet6}, {address, "::1"}, {port, 8053}, {family, inet6}]
        ]
    ),
    ?assertEqual(
        [
            [{name, example_inet}, {address, {127, 0, 0, 1}}, {port, 8053}, {family, inet}, {processes, 1}, {with_tcp, true}],
            [{name, example_inet6}, {address, {0, 0, 0, 0, 0, 0, 0, 1}}, {port, 8053}, {family, inet6}, {processes, 1}, {with_tcp, true}]
        ],
        erldns_config:get_servers()
    ).
