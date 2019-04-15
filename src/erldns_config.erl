%% Copyright (c) 2012-2018, DNSimple Corporation
%%
%% Permission to use, copy, modify, and/or distribute this software for any
%% purpose with or without fee is hereby granted, provided that the above
%% copyright notice and this permission notice appear in all copies.
%%
%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
%% WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
%% MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
%% ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
%% WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
%% ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
%% OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

%% @doc Provide application-wide configuration access.
-module(erldns_config).

-export([
         get_servers/0,
         get_address/1,
         get_port/0,
         get_num_workers/0
        ]).
-export([
         use_root_hints/0
        ]).
-export([
         packet_cache_enabled/0,
         packet_cache_default_ttl/0,
         packet_cache_sweep_interval/0,
         packet_cache_ttl_overrides/0
        ]).
-export([
         zone_delegates/0,
         zone_server_env/0,
         zone_server_max_processes/0,
         zone_server_protocol/0,
         zone_server_host/0,
         zone_server_port/0
        ]).
-export([
         websocket_env/0,
         websocket_protocol/0,
         websocket_host/0,
         websocket_port/0,
         websocket_path/0,
         websocket_url/0
        ]).

-export([
         storage_env/0,
         storage_type/0,
         storage_user/0,
         storage_pass/0,
         storage_host/0,
         storage_port/0,
         storage_dir/0
        ]).

-export([
         keyget/2,
         keyget/3
        ]).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-define(DEFAULT_IPV4_ADDRESS, {127,0,0,1}).
-define(DEFAULT_IPV6_ADDRESS, {0,0,0,0,0,0,0,1}).
-define(DEFAULT_PORT, 53).
-define(DEFAULT_NUM_WORKERS, 10).
-define(DEFAULT_CACHE_TTL, 20).
-define(DEFAULT_SWEEP_INTERVAL, 1000 * 60 * 3). % Every 3 minutes
-define(DEFAULT_ZONE_SERVER_PORT, 443).
-define(DEFAULT_WEBSOCKET_PATH, "/ws").

get_servers() ->
  case application:get_env(erldns, servers) of
    {ok, Servers} ->
      lists:map(
        fun(Server) ->
            [
             {name, keyget(name, Server)},
             {address, parse_address(keyget(address, Server))},
             {port, keyget(port, Server)},
             {family, keyget(family, Server)},
             {processes, keyget(processes, Server, 1)}
            ]
        end, Servers);
    _ -> []
  end.

-ifdef(TEST).
get_servers_undefined_test() ->
  ?assertEqual([], get_servers()).

get_servers_empty_list_test() ->
  application:set_env(erldns, servers, []),
  ?assertEqual([], get_servers()).


get_servers_single_server_test() ->
  application:set_env(erldns, servers, [[{name, example}, {address, "127.0.0.1"}, {port, 8053}, {family, inet}]]),
  ?assertEqual([
                [{name, example}, {address, {127,0,0,1}}, {port, 8053}, {family, inet}, {processes, 1}]
               ], get_servers()).

get_servers_multiple_servers_test() ->
  application:set_env(erldns, servers, [
                                        [{name, example_inet}, {address, "127.0.0.1"}, {port, 8053}, {family, inet}],
                                        [{name, example_inet6}, {address, "::1"}, {port, 8053}, {family, inet6}]
                                       ]),
  ?assertEqual([
                [{name, example_inet}, {address, {127,0,0,1}}, {port, 8053}, {family, inet}, {processes, 1}],
                [{name, example_inet6}, {address, {0,0,0,0,0,0,0,1}}, {port, 8053}, {family, inet6}, {processes, 1}]
               ], get_servers()).

-endif.

%% @doc Get the IP address (either IPv4 or IPv6) that the DNS server
%% should listen on.
%%
%% IPv4 default: 127.0.0.1
%% IPv6 default: ::1
-spec get_address(inet | inet6) -> inet:ip_address().
get_address(inet) ->
  case application:get_env(erldns, inet4) of
    {ok, Address} -> parse_address(Address);
    _ -> ?DEFAULT_IPV4_ADDRESS
  end;
get_address(inet6) ->
  case application:get_env(erldns, inet6) of
    {ok, Address} -> parse_address(Address);
    _ -> ?DEFAULT_IPV6_ADDRESS
  end.

%% @doc The the port that the DNS server should listen on.
%%
%% Default: 53
-spec get_port() -> inet:port_number().
get_port() ->
  case application:get_env(erldns, port) of
    {ok, Port} -> Port;
    _ -> ?DEFAULT_PORT
  end.

%% @doc Get the number of workers to run for handling DNS requests.
%%
%% Default: 10
-spec get_num_workers() -> non_neg_integer().
get_num_workers() ->
  case application:get_env(erldns, num_workers) of
    {ok, NumWorkers} -> NumWorkers;
    _ -> ?DEFAULT_NUM_WORKERS
  end.

-spec use_root_hints() -> boolean().
use_root_hints() ->
  case application:get_env(erldns, use_root_hints) of
    {ok, Flag} -> Flag;
    _ -> true
  end.

packet_cache() ->
  application:get_env(erldns, packet_cache, []).

packet_cache_enabled() ->
  keyget(enabled, packet_cache(), true).

packet_cache_default_ttl() ->
  keyget(default_ttl, packet_cache(), ?DEFAULT_CACHE_TTL).

packet_cache_sweep_interval() ->
  keyget(sweep_interval, packet_cache(), ?DEFAULT_SWEEP_INTERVAL).

packet_cache_ttl_overrides() ->
  keyget(ttl_overrides, packet_cache(), []).

keyget(Key, Data) ->
  keyget(Key, Data, undefined).

keyget(Key, Data, Default) ->
  case lists:keyfind(Key, 1, Data) of
    false ->
      Default;
    {Key, Value} ->
      Value
  end.


%% Zone server configuration
%% TODO: remove as zone server client logic has been removed

zone_delegates() ->
    application:get_env(erldns, zone_delegates, []).

zone_server_env() ->
  {ok, ZoneServerEnv} = application:get_env(erldns, zone_server),
  ZoneServerEnv.

zone_server_max_processes() ->
  keyget(max_processes, zone_server_env(), 16).

zone_server_protocol() ->
  keyget(protocol, zone_server_env(), "https").

zone_server_host() ->
  keyget(host, zone_server_env(), "localhost").

zone_server_port() ->
  keyget(port, zone_server_env(), ?DEFAULT_ZONE_SERVER_PORT).

websocket_env() ->
  keyget(websocket, zone_server_env(), []).

websocket_protocol() ->
  keyget(protocol, websocket_env(), wss).

websocket_host() ->
  keyget(host, websocket_env(), zone_server_host()).

websocket_port() ->
  keyget(port, websocket_env(), zone_server_port()).

websocket_path() ->
  keyget(path, websocket_env(), ?DEFAULT_WEBSOCKET_PATH).

websocket_url() ->
  atom_to_list(websocket_protocol()) ++ "://" ++ websocket_host() ++ ":" ++ integer_to_list(websocket_port()) ++ websocket_path().

%% Storage configuration

storage_type() ->
  storage_get(type).

storage_dir() ->
  storage_get(dir).

storage_user() ->
  storage_get(user).

storage_pass() ->
  storage_get(pass).

storage_host() ->
  storage_get(host).

storage_port() ->
  storage_get(port).

storage_env() ->
  get_env(storage).

storage_get(Key) ->
  get_env_value(Key, storage).

% Private functions

parse_address(Address) when is_list(Address) ->
  {ok, Tuple} = inet_parse:address(Address),
  Tuple;
parse_address(Address) -> Address.

get_env_value(Key, Name) ->
  case lists:keyfind(Key, 1, get_env(Name)) of
    false ->
      undefined;
    {Key, Value} ->
      Value
  end.


get_env(storage) ->
  case application:get_env(erldns, storage) of
    undefined ->
      [{type, erldns_storage_json},
       {dir, undefined},
       {user, undefined},
       {pass, undefined},
       {host, undefined},
       {port, undefined}];
    {ok, Env} ->
      Env
  end.
