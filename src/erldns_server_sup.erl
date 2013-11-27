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

%% @doc The general server supervisor. Starts the UDP and TCP listers on both
%% IPv4 and IPv6 ports. Also runs the zone checker *after* the UDP and TCP
%% servers are running.
-module(erldns_server_sup).
-behavior(supervisor).

% API
-export([start_link/0]).

% Supervisor hooks
-export([init/1]).

-define(SUPERVISOR, ?MODULE).

%% Helper macro for declaring children of supervisor
-define(CHILD(I, Type, Args), {I, {I, start_link, Args}, permanent, 5000, Type, [I]}).

%% Public API
start_link() ->
  supervisor:start_link({local, ?SUPERVISOR}, ?MODULE, []).

init(_Args) ->
  ServerProcs = [
    {udp_inet, {erldns_udp_server, start_link, [udp_inet, inet]}, permanent, 5000, worker, [erldns_udp_server]},
    {udp_inet6, {erldns_udp_server, start_link, [udp_inet6, inet6]}, permanent, 5000, worker, [erldns_udp_server]},
    {tcp_inet, {erldns_tcp_server, start_link, [tcp_inet, inet]}, permanent, 5000, worker, [erldns_tcp_server]},
    {tcp_inet6, {erldns_tcp_server, start_link, [tcp_inet6, inet6]}, permanent, 5000, worker, [erldns_tcp_server]}
  ],

  {ok, {{one_for_one, 20, 10}, ServerProcs}}.
