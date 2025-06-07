%% Copyright (c) 2012-2020, DNSimple Corporation
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

-module(erldns_config).
-moduledoc "Provide application-wide configuration access.".

-export([use_root_hints/0]).
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
-export([
    keyget/2,
    keyget/3
]).
-export([
    ingress_udp_request_timeout/0,
    ingress_tcp_request_timeout/0
]).

-define(DEFAULT_ZONE_SERVER_PORT, 443).
-define(DEFAULT_WEBSOCKET_PATH, "/ws").
-define(DEFAULT_UDP_PROCESS_TIMEOUT, 500).
-define(DEFAULT_TCP_PROCESS_TIMEOUT, 1000).

-spec use_root_hints() -> boolean().
use_root_hints() ->
    case application:get_env(erldns, use_root_hints) of
        {ok, Flag} ->
            Flag;
        _ ->
            true
    end.

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
    atom_to_list(websocket_protocol()) ++ "://" ++ websocket_host() ++ ":" ++
        integer_to_list(websocket_port()) ++ websocket_path().

-spec ingress_udp_request_timeout() -> non_neg_integer().
ingress_udp_request_timeout() ->
    case application:get_env(erldns, ingress_udp_request_timeout) of
        {ok, UdpTimeout} ->
            UdpTimeout;
        _ ->
            ?DEFAULT_UDP_PROCESS_TIMEOUT
    end.

-spec ingress_tcp_request_timeout() -> non_neg_integer().
ingress_tcp_request_timeout() ->
    case application:get_env(erldns, ingress_tcp_request_timeout) of
        {ok, TcpTimeout} ->
            TcpTimeout;
        _ ->
            ?DEFAULT_TCP_PROCESS_TIMEOUT
    end.
