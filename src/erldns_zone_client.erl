-module(erldns_zone_client).

-behaviour(websocket_client_handler).

-include("dns.hrl").
-include("erldns.hrl").

-export([
         start_link/0,
         fetch_zones/0,
         fetch_zone/1,
         init/1,
         websocket_handle/2,
         websocket_info/2,
         websocket_terminate/2
        ]).

% Public API
start_link() ->
  WsProtocol = websocket_protocol(),
  WsHost = websocket_host(),
  WsPort = websocket_port(),
  WsPath = websocket_path(),
  lager:info("Starting websocket client (protocol=~p, host=~p, port=~p, path=~p)", [WsProtocol, WsHost, WsPort, WsPath]),
  StartLinkResult = websocket_client:start_link(?MODULE, WsProtocol, WsHost, WsPort, WsPath, []),
  {ok, StartLinkResult}.

fetch_zones() ->
  case httpc:request(get, {zones_url(), [auth_header()]}, [], [{body_format, binary}]) of
    {ok, {{_Version, 200, _ReasonPhrase}, _Headers, Body}} ->
      lager:info("Parsing zones JSON"),
      JsonZones = jsx:decode(Body),
      lager:info("Putting zones into cache"),
      lists:foreach(
        fun(JsonZone) ->
            Zone = erldns_zone_parser:zone_to_erlang(JsonZone),
            erldns_zone_cache:put_zone(Zone)
        end, JsonZones),
      lager:info("Put ~p zones into cache", [length(JsonZones)]),
      {ok, length(JsonZones)};
    {_, {{_Version, Status, ReasonPhrase}, _Headers, _Body}} ->
      lager:error("Failed to load zones: ~p (status: ~p)", [ReasonPhrase, Status]),
      {err, Status, ReasonPhrase}
  end.

fetch_zone(Name) ->
  fetch_zone(Name,  zones_url() ++ binary_to_list(Name)).

fetch_zone(Name, Url) ->
  case httpc:request(get, {Url, [auth_header()]}, [], [{body_format, binary}]) of
    {ok, {{_Version, 200, _ReasonPhrase}, _Headers, Body}} ->
      lager:info("Parsing zone JSON"),
      Zone = erldns_zone_parser:zone_to_erlang(jsx:decode(Body)),
      lager:info("Putting ~p into zone cache", [Name]),
      erldns_zone_cache:put_zone(Zone);
    {_, {{_Version, Status, ReasonPhrase}, _Headers, _Body}} ->
      lager:error("Failed to load zone: ~p (status: ~p)", [ReasonPhrase, Status]),
      {err, Status, ReasonPhrase}
  end.

% Websocket Callbacks

init([]) ->
  lager:info("init() websocket client"),
  self() ! authenticate,
  {ok, 2}.

websocket_handle({_Type, Msg}, State) ->
  ZoneNotification = jsx:decode(Msg),
  lager:info("Zone notification received: ~p", [ZoneNotification]),
  case ZoneNotification of
    [{<<"name">>, Name}, {<<"url">>, Url}, {<<"action">>, Action}] ->
      case Action of
        <<"create">> ->
          lager:debug("Creating zone ~p", [Name]),
          fetch_zone(Name, binary_to_list(Url));
        <<"update">> ->
          lager:debug("Updating zone ~p", [Name]),
          fetch_zone(Name, binary_to_list(Url));
        <<"delete">> ->
          erldns_zone_cache:delete_zone(Name),
          lager:debug("Deleting zone ~p", [Name]);
        _ ->
          lager:error("Unsupported action: ~p", [Action])
      end;
    _ ->
      lager:error("Unsupported zone notification message: ~p", [ZoneNotification])
  end,
  {ok, State}.

websocket_info(authenticate, State) ->
  EncodedCredentials = encoded_credentials(),
  lager:debug("Authenticating with ~p", [EncodedCredentials]),
  {reply, {text, list_to_binary("Authorization: " ++ EncodedCredentials)}, State};

websocket_info(Atom, State) ->
  lager:debug("websocket_info(~p, ~p)", [Atom, State]),
  {ok, State}.

websocket_terminate(Message, State) ->
  lager:debug("websocket_terminate(~p, ~p)", [Message, State]),
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
  proplists:get_value(port, zone_server_env(), 433).

websocket_env() ->
  proplists:get_value(websocket, zone_server_env(), []).

websocket_protocol() ->
  proplists:get_value(protocol, websocket_env(), "wss").

websocket_host() ->
  proplists:get_value(host, websocket_env(), zone_server_host()).

websocket_port() ->
  proplists:get_value(port, websocket_env(), zone_server_port()).

websocket_path() ->
  proplists:get_value(path, websocket_env(), "/ws").

zones_url() ->
  zone_server_protocol() ++ "://" ++ zone_server_host() ++ ":" ++ integer_to_list(zone_server_port()) ++ "/zones/".

encoded_credentials() ->
  case application:get_env(erldns, credentials) of
    {ok, {Username, Password}} ->
      lager:debug("Sending ~p:~p for authentication", [Username, Password]),
      base64:encode_to_string(lists:append([Username,":",Password]))
  end.

auth_header() ->
  {"Authorization","Basic " ++ encoded_credentials()}.

