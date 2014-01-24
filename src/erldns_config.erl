%% Copyright (c) 2012-2013, Aetrion LLC
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
    get_address/1,
    get_port/0,
    get_num_workers/0
  ]).
-export([
    use_root_hints/0
  ]).
-export([
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

-define(DEFAULT_IPV4_ADDRESS, {127,0,0,1}).
-define(DEFAULT_IPV6_ADDRESS, {0,0,0,0,0,0,0,1}).
-define(DEFAULT_PORT, 53).
-define(DEFAULT_NUM_WORKERS, 10).
-define(DEFAULT_ZONE_SERVER_PORT, 443).
-define(DEFAULT_WEBSOCKET_PATH, "/ws").

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

% Private functions

parse_address(Address) when is_list(Address) ->
  {ok, Tuple} = inet_parse:address(Address),
  Tuple;
parse_address(Address) -> Address.

zone_server_env() ->
  {ok, ZoneServerEnv} = application:get_env(erldns, zone_server),
  ZoneServerEnv.

zone_server_max_processes() ->
  proplists:get_value(max_processes, zone_server_env(), 16).

zone_server_protocol() ->
  proplists:get_value(protocol, zone_server_env(), "https").

zone_server_host() ->
  proplists:get_value(host, zone_server_env(), "localhost").

zone_server_port() ->
  proplists:get_value(port, zone_server_env(), ?DEFAULT_ZONE_SERVER_PORT).

websocket_env() ->
  proplists:get_value(websocket, zone_server_env(), []).

websocket_protocol() ->
  proplists:get_value(protocol, websocket_env(), wss).

websocket_host() ->
  proplists:get_value(host, websocket_env(), zone_server_host()).

websocket_port() ->
  proplists:get_value(port, websocket_env(), zone_server_port()).

websocket_path() ->
  proplists:get_value(path, websocket_env(), ?DEFAULT_WEBSOCKET_PATH).

websocket_url() ->
  atom_to_list(websocket_protocol()) ++ "://" ++ websocket_host() ++ ":" ++ integer_to_list(websocket_port()) ++ websocket_path().
