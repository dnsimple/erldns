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

-export([
    use_root_hints/0,
    ingress_udp_request_timeout/0,
    ingress_tcp_request_timeout/0
]).
-export([
    keyget/2,
    keyget/3
]).

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

-doc false.
keyget(Key, Data) ->
    keyget(Key, Data, undefined).

-doc false.
keyget(Key, Data, Default) ->
    case lists:keyfind(Key, 1, Data) of
        false ->
            Default;
        {Key, Value} ->
            Value
    end.

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
