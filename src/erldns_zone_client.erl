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

%% @doc A websocket handler and API for retreiving zone data from the zone
%% server.
-module(erldns_zone_client).

-behaviour(websocket_client_handler).

-include_lib("dns/include/dns.hrl").
-include("erldns.hrl").

% Public API
-export([
    websocket_url/0,
    fetch_zones/0,
    fetch_zone/1,
    fetch_zone/2
  ]).

% Websocket callbacks
-export([
    init/2,
    websocket_handle/3,
    websocket_info/3,
    websocket_terminate/3]).

-record(state, {}).

-define(DEFAULT_ZONE_SERVER_PORT, 443).
-define(DEFAULT_WEBSOCKET_PATH, "/ws").

% Public API
websocket_url() ->
  atom_to_list(websocket_protocol()) ++ "://" ++ websocket_host() ++ ":" ++ integer_to_list(websocket_port()) ++ websocket_path().

fetch_zones() ->
  case httpc:request(get, {zones_url(), headers()}, [], [{body_format, binary}]) of
    {ok, {{_Version, 200, _ReasonPhrase}, _Headers, Body}} ->
      JsonZones = jsx:decode(Body),
      hottub:start_link(zone_fetcher, zone_server_max_processes(), erldns_zone_fetcher, start_link, []),
      erldns_zone_fetcher_countdown:set_remaining(length(JsonZones)),
      lager:info("Putting zones into cache"),
      lists:foreach(
        fun([{<<"name">>, Name}, {<<"sha">>, Sha}, _]) ->
            hottub:cast(zone_fetcher, {fetch_zone, Name, Sha})
        end, JsonZones),
      {ok, 0};
    {_, {{_Version, Status, ReasonPhrase}, _Headers, _Body}} ->
      lager:error("Failed to load zones: ~p (status: ~p)", [ReasonPhrase, Status]),
      {err, Status, ReasonPhrase};
    {error, Error} ->
      {err, Error}
  end.

fetch_zone(Name) ->
  do_fetch_zone(Name, zone_url(Name)).

fetch_zone(Name, Sha) ->
  do_fetch_zone(Name, zone_url(Name, Sha)).

do_fetch_zone(Name, Url) ->
  case httpc:request(get, {Url, [auth_header()]}, [], [{body_format, binary}]) of
    {ok, {{_Version, 200, _ReasonPhrase}, _Headers, Body}} ->
      safe_process_json_zone(jsx:decode(Body), 'cast');
    {_, {{_Version, Status = 304, ReasonPhrase}, _Headers, _Body}} ->
      %lager:debug("Zone not modified: ~p", [Name]),
      {ok, Status, ReasonPhrase};
    {_, {{_Version, Status = 404, ReasonPhrase}, _Headers, _Body}} ->
      erldns_zone_cache:delete_zone(Name),
      {err, Status, ReasonPhrase};
    {_, {{_Version, Status, ReasonPhrase}, _Headers, _Body}} ->
      lager:error("Failed to load zone: ~p (status: ~p)", [ReasonPhrase, Status]),
      {err, Status, ReasonPhrase};
    {error, Reason} ->
      lager:error("Failed to load zone due to server error: ~p", [Reason]),
      {err, Reason}
  end.

%safe_process_json_zone(JsonZone) ->
%  safe_process_json_zone(JsonZone, 'call').
safe_process_json_zone(JsonZone, MessageType) ->
  try process_json_zone(JsonZone, MessageType) of
    Zone -> Zone
  catch
    Exception:Reason ->
      lager:error("Error parsing JSON zone (~p : ~p)", [Exception, Reason])
  end.

process_json_zone(JsonZone, 'call') ->
  Zone = erldns_zone_parser:zone_to_erlang(JsonZone),
  erldns_zone_cache:put_zone(Zone);
process_json_zone(JsonZone, 'cast') ->
  Zone = erldns_zone_parser:zone_to_erlang(JsonZone),
  {Name, Version, _Records} = Zone,
  lager:debug("Put zone async: ~p (~p)", [Name, Version]),
  erldns_zone_cache:put_zone_async(Zone).

% Websocket Callbacks

init([], _ConnState) ->
  %self() ! authenticate,
  {ok, #state{}}.

websocket_handle({_Type, Msg}, _ConnState, State) ->
  ZoneNotification = jsx:decode(Msg),
  lager:debug("Zone notification received: ~p", [ZoneNotification]),
  case ZoneNotification of
    [{<<"name">>, Name}, {<<"sha">>, _Version}, {<<"url">>, Url}, {<<"action">>, Action}] ->
      case Action of
        <<"create">> ->
          lager:debug("Creating zone ~p", [Name]),
          do_fetch_zone(Name, binary_to_list(Url));
        <<"update">> ->
          lager:debug("Updating zone ~p", [Name]),
          do_fetch_zone(Name, binary_to_list(Url));
        <<"delete">> ->
          lager:debug("Deleting zone ~p", [Name]),
          erldns_zone_cache:delete_zone(Name);
        _ ->
          lager:error("Unsupported action: ~p", [Action])
      end;
    _ ->
      lager:error("Unsupported zone notification message: ~p", [ZoneNotification])
  end,
  {reply, {text, <<"received">>}, State}.

websocket_info(authenticate, _ConnState, State) ->
  EncodedCredentials = encoded_credentials(),
  %lager:debug("Authenticating with ~p", [EncodedCredentials]),
  {reply, {text, list_to_binary("Authorization: " ++ EncodedCredentials)}, State};

websocket_info(Message, _ConnState, State) ->
  lager:debug("websocket_info(~p)", [Message]),
  {ok, State}.

websocket_terminate(_Message, _ConnState, _State) ->
  ok.

%% Internal functions

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

zones_url() ->
  zone_server_protocol() ++ "://" ++ zone_server_host() ++ ":" ++ integer_to_list(zone_server_port()) ++ "/zones/".

zone_url(Name) ->
  zones_url() ++ binary_to_list(Name).

zone_url(Name, Version) ->
  zones_url() ++ binary_to_list(Name) ++ "/" ++ binary_to_list(Version).

encoded_credentials() ->
  case application:get_env(erldns, credentials) of
    {ok, {Username, Password}} ->
      %lager:debug("Sending ~p:~p for authentication", [Username, Password]),
      base64:encode_to_string(lists:append([Username,":",Password]))
  end.

auth_header() ->
  {"Authorization","Basic " ++ encoded_credentials()}.

headers() ->
  [auth_header(), {"X-Zone-No-Records", "1"}].
