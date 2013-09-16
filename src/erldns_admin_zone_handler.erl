-module(erldns_admin_zone_handler).

-export([init/3]).
-export([content_types_provided/2, is_authorized/2]).
-export([to_html/2, to_json/2, to_text/2]).

-include("dns.hrl").
-include("erldns.hrl").

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
  {Name, _} = cowboy_req:binding(name, Req),
  {ok, Zone} = erldns_zone_cache:get_zone_with_records(Name),
  lager:debug("Zone: ~p", [Zone]),
  RecordsForJson = lists:map(
    fun(Record) ->
       erldns_zone_encoder:encode_record(Record) 
    end, Zone#zone.records),

  Body = jsx:encode([{<<"erldns">>, 
        [
          {<<"zone">>, [
              {<<"name">>, Zone#zone.name},
              {<<"version">>, Zone#zone.version},
              {<<"records">>, RecordsForJson}
            ]}
        ]
      }]),
  {Body, Req, State}.
