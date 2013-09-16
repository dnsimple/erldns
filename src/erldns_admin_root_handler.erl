-module(erldns_admin_root_handler).

-export([init/3]).
-export([content_types_provided/2, is_authorized/2]).
-export([to_html/2, to_json/2, to_text/2]).

init(_Transport, _Req, []) ->
  {upgrade, protocol, cowboy_rest}.

content_types_provided(Req, State) ->
  {[
      {<<"text/html">>, to_html},
      {<<"text/plain">>, to_text},
      {<<"application/json">>, to_json}
    ], Req, State}.

is_authorized(Req, State) ->
  erldns_admin:is_authorized(Req, State).

to_html(Req, State) ->
  {<<"erldns admin">>, Req, State}.

to_text(Req, State) ->
  {<<"erldns admin">>, Req, State}.

to_json(Req, State) ->
  ZoneNamesAndVersionsForJson = lists:map(
    fun({Name, Version}) -> 
        [{<<"name">>, Name}, {<<"version">>, Version}]
    end, erldns_zone_cache:zone_names_and_versions()),

  Body = jsx:encode([{<<"erldns">>, 
        [
          {<<"zones">>, [
              {<<"count">>, length(ZoneNamesAndVersionsForJson)},
              {<<"versions">>, ZoneNamesAndVersionsForJson} 
            ]}
        ]
      }]),
  {Body, Req, State}.
