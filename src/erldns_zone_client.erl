-module(erldns_zone_client).

-behaviour(websocket_client_handler).

-include("dns.hrl").
-include("erldns.hrl").

% Public API
-export([
    websocket_url/0,
    fetch_zones/0,
    fetch_zone/1,
    check_zone/2
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
  case httpc:request(get, {zones_url(), [auth_header()]}, [], [{body_format, binary}]) of
    {ok, {{_Version, 200, _ReasonPhrase}, _Headers, Body}} ->
      JsonZones = jsx:decode(Body),
      lager:info("Putting zones into cache"),
      lists:foreach(fun safe_process_json_zone/1, JsonZones),
      lager:info("Put ~p zones into cache", [length(JsonZones)]),
      {ok, length(JsonZones)};
    {_, {{_Version, Status, ReasonPhrase}, _Headers, _Body}} ->
      lager:error("Failed to load zones: ~p (status: ~p)", [ReasonPhrase, Status]),
      {err, Status, ReasonPhrase};
    {error, Error} ->
      {err, Error}
  end.

safe_process_json_zone(JsonZone) ->
  try process_json_zone(JsonZone) of
    Zone -> Zone
  catch
    Exception:Reason ->
      lager:error("Error parsing JSON zone (~p : ~p)", [Exception, Reason])
  end.

process_json_zone(JsonZone) ->
  Zone = erldns_zone_parser:zone_to_erlang(JsonZone),
  %lager:debug("Putting zone ~p into cache", [Zone]),
  erldns_zone_cache:put_zone(Zone).

fetch_zone(Name) ->
  fetch_zone(Name,  zone_url(Name)).

fetch_zone(Name, Url) ->
  case httpc:request(get, {Url, [auth_header()]}, [], [{body_format, binary}]) of
    {ok, {{_Version, 200, _ReasonPhrase}, _Headers, Body}} ->
      safe_process_json_zone(jsx:decode(Body));
    {_, {{_Version, Status = 404, ReasonPhrase}, _Headers, _Body}} ->
      erldns_zone_cache:delete_zone(Name),
      {err, Status, ReasonPhrase};
    {_, {{_Version, Status, ReasonPhrase}, _Headers, _Body}} ->
      lager:error("Failed to load zone: ~p (status: ~p)", [ReasonPhrase, Status]),
      {err, Status, ReasonPhrase}
  end.

check_zone(_Name, []) ->
  ok;
check_zone(Name, Sha) ->
  check_zone(Name, Sha, zone_check_url(Name, Sha)).

check_zone(Name, _Sha, Url) ->
  %lager:debug("check_zone(~p) (url: ~p)", [Name, Url]),
  case httpc:request(head, {Url, [auth_header()]}, [], [{body_format, binary}]) of
    {ok, {{_Version, 200, _ReasonPhrase}, _Headers, _Body}} ->
      lager:debug("Zone appears to have changed for ~p", [Name]),
      ok;
    {ok, {{_Version, 304, _ReasonPhrase}, _Headers, _Body}} ->
      %lager:debug("Zone has not changed for ~p", [Name]),
      ok;
    {ok, {{_Version, 404, _ReasonPhrase}, _Headers, _Body}} ->
      lager:debug("Zone server returned 404 for ~p, removing zone", [Url]),
      erldns_zone_cache:delete_zone(Name),
      ok;
    {_, {{_Version, Status, ReasonPhrase}, _Headers, _Body}} ->
      lager:error("Failed to send zone check for ~p: ~p (status: ~p)", [Name, ReasonPhrase, Status]),
      {err, Status, ReasonPhrase}
  end.

% Websocket Callbacks

init([], _ConnState) ->
  %self() ! authenticate,
  {ok, #state{}}.

websocket_handle({_Type, Msg}, _ConnState, State) ->
  ZoneNotification = jsx:decode(Msg),
  lager:debug("Zone notification received: ~p", [ZoneNotification]),
  case ZoneNotification of
    [{<<"name">>, Name}, {<<"sha">>, _Sha}, {<<"url">>, Url}, {<<"action">>, Action}] ->
      case Action of
        <<"create">> ->
          lager:debug("Creating zone ~p", [Name]),
          fetch_zone(Name, binary_to_list(Url));
        <<"update">> ->
          lager:debug("Updating zone ~p", [Name]),
          fetch_zone(Name, binary_to_list(Url));
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
  {reply, {text, list_to_binary("Authorization: " ++ EncodedCredentials)}, State}.

websocket_terminate(_Message, _ConnState, _State) ->
  ok.

%% Internal functions

zone_server_env() ->
  {ok, ZoneServerEnv} = application:get_env(erldns, zone_server),
  ZoneServerEnv.

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

zone_check_url(Name, Sha) ->
  zones_url() ++ binary_to_list(Name) ++ "/" ++ binary_to_list(Sha).

encoded_credentials() ->
  case application:get_env(erldns, credentials) of
    {ok, {Username, Password}} ->
      %lager:debug("Sending ~p:~p for authentication", [Username, Password]),
      base64:encode_to_string(lists:append([Username,":",Password]))
  end.

auth_header() ->
  {"Authorization","Basic " ++ encoded_credentials()}.
