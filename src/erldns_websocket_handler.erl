-module(erldns_websocket_handler).

-behaviour(websocket_client_handler).

% Websocket callbacks
-export([
    init/2,
    websocket_handle/3,
    websocket_info/3,
    websocket_terminate/3
  ]).

-record(state, {}).

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
          erldns_zone_client:do_fetch_zone(Name, binary_to_list(Url));
        <<"update">> ->
          lager:debug("Updating zone ~p", [Name]),
          erldns_zone_client:do_fetch_zone(Name, binary_to_list(Url));
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
  EncodedCredentials = erldns_config:encoded_credentials(),
  %lager:debug("Authenticating with ~p", [EncodedCredentials]),
  {reply, {text, list_to_binary("Authorization: " ++ EncodedCredentials)}, State};

websocket_info(Message, _ConnState, State) ->
  lager:debug("websocket_info(~p)", [Message]),
  {ok, State}.

websocket_terminate(_Message, _ConnState, _State) ->
  ok.
