-module(erldns_admin).
-moduledoc """
Erldns admin API.

### Configuration:
This application will read from your `sys.config` the following example:
```erlang
{erldns, [
    {admin, [
        {port, 8083},
        {tls, false},
        {credentials, {~"username", ~"password"}},
        {middleware, [my_custom_middleware, another_middleware]},
        {routes, [{~"/custom/:action", my_custom_route_handler, #{}}]}
    ]}
]}
```

The accepted values are:
- `port`: an integer between `1` and `65535` indicating the port to listen on
    (default: `8083` without TLS and `8483` when TLS is enabled).
- `tls`: `false`, or `{true, SslOpts}` where `SslOpts` is a list of `t:ssl:tls_server_option/0`,
    indicating whether to use TLS (default: `false`).
- `credentials`: `false` if no authentication is required, or a tuple of `{Username, Password}`
    binary strings. If configured, all routes will require authentication (default: `false`).
- `middleware`: an optional list of cowboy compliant middleware modules to apply
    to all admin API requests (default: `[]`).
- `routes`: an optional list of additional routes to add to the admin API.
    This is a list of `cowboy_router:route_path()` elements that will be prepended
    to the default routes (default: `[]`).
""".

-define(DEFAULT_CLEAR_PORT, 8083).
-define(DEFAULT_TLS_PORT, 8483).
-define(LOG_METADATA, #{domain => [erldns, admin]}).

-include_lib("kernel/include/logger.hrl").

-export([maybe_start/0]).

-ifdef(TEST).
-export_type([env/0]).
-endif.

-doc """
Configuration parameters, see the module documentation for details.
""".
-type config() :: #{
    port := 0..65535,
    tls := false | [ssl:tls_server_option()],
    credentials := false | {binary(), binary()},
    middleware => [module()],
    routes => cowboy_router:routes()
}.

-type env() :: [{atom(), term()}].

-spec maybe_start() -> ok | {ok, pid()} | {error, term()}.
maybe_start() ->
    case ensure_valid_config() of
        disabled ->
            ok;
        error ->
            error(bad_configuration);
        Config ->
            start(Config)
    end.

-spec start(config()) -> {ok, pid()} | {error, term()}.
start(
    #{
        tls := Tls,
        port := Port,
        credentials := Credentials,
        middleware := Middleware,
        routes := AdditionalRoutes
    }
) ->
    Dispatch = cowboy_router:compile(default_routes(AdditionalRoutes)),
    persistent_term:put(?MODULE, Dispatch),
    ProtocolOpts = #{
        env => #{dispatch => {persistent_term, ?MODULE}, credentials => Credentials},
        middlewares => middlewares(Middleware, Credentials)
    },
    case Tls of
        false ->
            TransportOpts = socket_opts(Port),
            cowboy:start_clear(?MODULE, #{socket_opts => TransportOpts}, ProtocolOpts);
        SslOpts ->
            TransportOpts = socket_opts(Port) ++ SslOpts,
            cowboy:start_tls(?MODULE, #{socket_opts => TransportOpts}, ProtocolOpts)
    end.

-spec middlewares([module()], false | dynamic()) -> [module()].
middlewares(Middleware, false) ->
    [cowboy_router] ++ Middleware ++ [cowboy_handler];
middlewares(Middleware, _) ->
    [erldns_admin_auth_middleware, cowboy_router] ++ Middleware ++ [cowboy_handler].

-spec default_routes([dynamic()]) -> cowboy_router:routes().
default_routes(AdditionalRoutes) ->
    DefaultRoutes = [
        {~"/", erldns_admin_root_handler, #{}},
        {~"/zones/:zonename", erldns_admin_zone_handler, #{}},
        {~"/zones/:zonename/records[/:record_name]", erldns_admin_zone_records_handler, #{}}
    ],
    [{'_', AdditionalRoutes ++ DefaultRoutes}].

-spec ensure_valid_config() -> error | disabled | config().
ensure_valid_config() ->
    maybe
        {ok, Env} ?= env(),
        {ok, Tls} ?= config_tls(Env),
        {ok, Port} ?= config_port(Env, Tls),
        {ok, Credentials} ?= config_credentials(Env),
        {ok, Middleware} ?= config_middleware(Env),
        {ok, Routes} ?= config_routes(Env),
        #{
            port => Port,
            tls => Tls,
            credentials => Credentials,
            middleware => Middleware,
            routes => Routes
        }
    end.

-spec socket_opts(inet:port_number()) -> [gen_tcp:option()].
socket_opts(Port) ->
    [
        inet6,
        {ipv6_v6only, false},
        {ip, any},
        {port, Port},
        {nodelay, true},
        {keepalive, true},
        {reuseport, true},
        {reuseport_lb, true}
    ].

-spec config_port(env(), false | {true, dynamic()}) -> {ok, 1..65535} | error.
config_port(Env, MaybeTls) ->
    DefaultPort =
        case MaybeTls of
            false -> ?DEFAULT_CLEAR_PORT;
            _ -> ?DEFAULT_TLS_PORT
        end,
    case proplists:get_value(port, Env, DefaultPort) of
        Port when is_integer(Port), 0 < Port, Port =< 65535 ->
            {ok, Port};
        OtherPort ->
            ?LOG_ERROR(
                #{what => erldns_admin_bad_config, port => OtherPort},
                ?LOG_METADATA
            ),
            error
    end.

-spec config_tls(env()) -> {ok, false | [ssl:tls_server_option()]} | error.
config_tls(Env) ->
    case proplists:get_value(tls, Env, false) of
        false ->
            {ok, false};
        {true, Opts} when is_list(Opts) ->
            {ok, Opts};
        Other ->
            ?LOG_ERROR(
                #{what => erldns_admin_bad_config, tls => Other},
                ?LOG_METADATA
            ),
            error
    end.

-spec config_credentials(env()) -> {ok, false | {binary(), binary()}} | error.
config_credentials(Env) ->
    case lists:keyfind(credentials, 1, Env) of
        false ->
            {ok, false};
        {credentials, {Username, Password}} when is_binary(Username), is_binary(Password) ->
            {ok, {Username, Password}};
        OtherValue ->
            ?LOG_ERROR(
                #{what => erldns_admin_bad_config, credentials => OtherValue},
                ?LOG_METADATA
            ),
            error
    end.

-spec config_middleware(env()) -> {ok, [module()]} | error.
config_middleware(Env) ->
    maybe
        {middleware, Modules} ?= lists:keyfind(middleware, 1, Env),
        [] ?= lists:filter(fun is_not_middleware/1, Modules),
        {ok, Modules}
    else
        false ->
            {ok, []};
        OtherValue ->
            ?LOG_ERROR(
                #{what => erldns_admin_bad_config, middleware => OtherValue},
                ?LOG_METADATA
            ),
            error
    end.

-spec is_not_middleware(module()) -> boolean().
is_not_middleware(Module) when is_atom(Module) ->
    not (is_atom(Module) andalso {module, Module} =:= code:ensure_loaded(Module) andalso
        erlang:function_exported(Module, execute, 2)).

-spec config_routes(env()) -> {ok, cowboy_router:routes()} | error.
config_routes(Env) ->
    maybe
        {routes, Routes} ?= lists:keyfind(routes, 1, Env),
        true ?= is_list(Routes),
        {ok, Routes}
    else
        false ->
            {ok, []};
        OtherValue ->
            ?LOG_ERROR(
                #{what => erldns_admin_bad_config, routes => OtherValue},
                ?LOG_METADATA
            ),
            error
    end.

-spec env() -> {ok, env()} | error | disabled.
env() ->
    case application:get_env(erldns, admin) of
        {ok, Env} when is_list(Env) -> {ok, Env};
        {ok, _} -> error;
        _ -> disabled
    end.
