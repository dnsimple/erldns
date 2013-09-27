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

%% @doc Supervisor for the websocket process. The websocket is used by the
%% zone server to send zone create/update/delete notifications. The websocket
%% is only used to notify though, actual data is pulled by the zone client.
-module(erldns_websocket_sup).
-behavior(supervisor).

% API
-export([start_link/0]).

% Supervisor hooks
-export([init/1]).

-define(SUPERVISOR, ?MODULE).

%% Public API
start_link() ->
  supervisor:start_link({local, ?SUPERVISOR}, ?MODULE, []).

init(_Args) ->
  WebsocketUrl = erldns_zone_client:websocket_url(),
  lager:debug("Connecting to web socket: ~p", [WebsocketUrl]),
  Procs = [
    {websocket_client, {websocket_client, start_link, [WebsocketUrl, erldns_zone_client, []]}, permanent, 5000, worker, [websocket_client]}
  ],

  {ok, {{one_for_one, 20, 10}, Procs}}.
