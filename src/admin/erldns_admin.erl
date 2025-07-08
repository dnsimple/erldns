-module(erldns_admin).
-moduledoc """
Erldns admin API.

### Configuration:
This application will read from your `sys.config` the following example:
```erlang
{erldns, [
    {admin, [
        {credentials, {<<"username">>, <<"password">>}},
        {port, 8083},
        {middleware, [my_custom_middleware, another_middleware]}
    ]}
]}
```
where `credentials` is a tuple of `username` and `password` as either strings or binaries,
`port` is a valid Unix port to listen on, and `middleware` is an optional list of
middleware modules that will be applied to all admin API requests.
""".

-define(DEFAULT_PORT, 8083).

-include_lib("kernel/include/logger.hrl").

-export([maybe_start/0, is_authorized/2]).

-ifdef(TEST).
-export([middleware/1]).
-export_type([env/0]).
-endif.

-doc """
Configuration parameters, see the module documentation for details.
""".
-type config() :: #{
    port := 0..65535,
    username := binary(),
    password := binary(),
    middleware => [module()]
}.

-doc "Common state for all handlers".
-opaque handler_state() :: #{
    username := binary(),
    password := binary()
}.
-export_type([config/0, handler_state/0]).

-type env() :: [{atom(), term()}].

-spec maybe_start() -> ok | {ok, pid()} | {error, term()}.
maybe_start() ->
    case ensure_valid_config() of
        disabled ->
            ok;
        false ->
            error(bad_configuration);
        Config ->
            start(Config)
    end.

-spec start(config()) -> {ok, pid()} | {error, term()}.
start(#{port := Port, username := Username, password := Password} = Config) ->
    State = #{username => Username, password => Password},
    Dispatch = cowboy_router:compile(
        [
            {'_', [
                {"/", erldns_admin_root_handler, State},
                {"/zones/:zone_name", erldns_admin_zone_resource_handler, State},
                {"/zones/:zone_name/records[/:record_name]",
                    erldns_admin_zone_records_resource_handler, State},
                {"/zones/:zone_name/:action", erldns_admin_zone_control_handler, State}
            ]}
        ]
    ),
    TransportOpts = #{socket_opts => [inet, {ip, {0, 0, 0, 0}}, {port, Port}]},
    Middleware = maps:get(middleware, Config, []),
    ProtocolOpts = #{
        env => #{dispatch => Dispatch},
        middlewares => [cowboy_router] ++ Middleware ++ [cowboy_handler]
    },
    cowboy:start_clear(?MODULE, TransportOpts, ProtocolOpts).

-doc false.
-spec is_authorized(cowboy_req:req(), handler_state()) ->
    {true | {false, iodata()}, cowboy_req:req(), handler_state()}
    | {stop, cowboy_req:req(), handler_state()}.
is_authorized(Req, #{username := ValidUsername, password := ValidPassword} = State) ->
    maybe
        {basic, GivenUsername, GivenPassword} ?= cowboy_req:parse_header(<<"authorization">>, Req),
        true ?= is_binary_of_equal_size(GivenUsername, ValidUsername),
        true ?= is_binary_of_equal_size(GivenPassword, ValidPassword),
        true ?= crypto:hash_equals(GivenUsername, ValidUsername) andalso
            crypto:hash_equals(GivenPassword, ValidPassword),
        {true, Req, State}
    else
        _ ->
            {{false, <<"Basic realm=\"erldns admin\"">>}, Req, State}
    end.

-spec is_binary_of_equal_size(term(), term()) -> boolean().
is_binary_of_equal_size(Bin1, Bin2) ->
    is_binary(Bin1) andalso is_binary(Bin2) andalso byte_size(Bin1) =:= byte_size(Bin2).

-spec ensure_valid_config() -> false | disabled | config().
ensure_valid_config() ->
    maybe
        {true, Env} ?= env(),
        {true, Port} ?= port(Env),
        {true, Username, Password} ?= credentials(Env),
        {true, Middleware} ?= middleware(Env),
        #{port => Port, username => Username, password => Password, middleware => Middleware}
    end.

-spec port(env()) -> {true, 1..65535} | false.
port(Env) ->
    case proplists:get_value(port, Env, ?DEFAULT_PORT) of
        Port when is_integer(Port), 0 < Port, Port =< 65535 ->
            {true, Port};
        OtherPort ->
            ?LOG_ERROR(
                #{what => erldns_admin_bad_config, port => OtherPort},
                #{domain => [erldns, admin]}
            ),
            false
    end.

-spec credentials(env()) -> {true, binary(), binary()} | false.
credentials(Env) ->
    case lists:keyfind(credentials, 1, Env) of
        {credentials, {Username, Password}} when is_list(Username), is_list(Password) ->
            {true, list_to_binary(Username), list_to_binary(Password)};
        {credentials, {Username, Password}} when is_binary(Username), is_binary(Password) ->
            {true, Username, Password};
        OtherValue ->
            ?LOG_ERROR(
                #{what => erldns_admin_bad_config, credentials => OtherValue},
                #{domain => [erldns, admin]}
            ),
            false
    end.

-spec middleware(env()) -> {true, [module()]}.
middleware(Env) ->
    case lists:keyfind(middleware, 1, Env) of
        {middleware, Modules} when is_list(Modules) ->
            case lists:all(fun is_atom/1, Modules) of
                true ->
                    {true, Modules};
                false ->
                    ?LOG_ERROR(
                        #{what => erldns_admin_bad_config, middleware => Modules},
                        #{domain => [erldns, admin]}
                    ),
                    {true, []}
            end;
        false ->
            {true, []};
        OtherValue ->
            ?LOG_ERROR(
                #{what => erldns_admin_bad_config, middleware => OtherValue},
                #{domain => [erldns, admin]}
            ),
            {true, []}
    end.

-spec env() -> {true, env()} | false | disabled.
env() ->
    case application:get_env(erldns, admin) of
        {ok, Env} when is_list(Env) -> {true, Env};
        {ok, _} -> false;
        _ -> disabled
    end.
