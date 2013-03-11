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
  lager:info("Starting websocket client"),
  StartLinkResult = websocket_client:start_link(?MODULE, wss, zone_server_host(), 443, "/ws", []),
  {ok, StartLinkResult}.

fetch_zones() ->
  case httpc:request(get, {zones_url(), [auth_header()]}, [], [{body_format, binary}]) of
    {ok, {{_Version, 200, _ReasonPhrase}, _Headers, Body}} ->
      lager:info("Parsing zones JSON"),
      Zones = erldns_zone_parser:zones_to_erlang(jsx:decode(Body)),
      lists:foreach(
        fun(Zone) ->
            erldns_zone_cache:put_zone(Zone)
        end, Zones),
      lager:info("Put ~p zones into cache", [length(Zones)]),
      {ok, length(Zones)};
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
zone_server_host() ->
  {ok, ZoneServerHost} = application:get_env(erldns, zone_server_host),
  ZoneServerHost.

zones_url() ->
  "https://" ++ zone_server_host() ++ "/zones/".

encoded_credentials() ->
  case application:get_env(erldns, credentials) of
    {ok, {Username, Password}} ->
      lager:debug("Sending ~p:~p for authentication", [Username, Password]),
      base64:encode_to_string(lists:append([Username,":",Password]))
  end.

auth_header() ->
  {"Authorization","Basic " ++ encoded_credentials()}.

