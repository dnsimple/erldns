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

%% @doc Cowboy handler that handles Admin API requests to /zones/:name/:action
%%
%% Currently only the "reload" action is supported.
-module(erldns_admin_zone_control_handler).

-export([init/3]).
-export([content_types_provided/2, is_authorized/2]).
-export([to_html/2, to_json/2, to_text/2]).

-include_lib("dns/include/dns.hrl").
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
  {Action, _} = cowboy_req:binding(action, Req),
  case Action of
    <<"reload">> ->
      lager:debug("Reloading ~p", [Name]),
      case erldns_zone_client:fetch_zone(Name) of
        Zone when is_record(Zone, zone) ->
          {erldns_zone_encoder:zone_to_json(Zone), Req, State};
        Result ->
          lager:debug("Fetch zone result: ~p", [Result]),
          {jsx:encode([]), Req, State}
      end;
    _ ->
      lager:debug("Unsupported action: ~p", [Name]),
      {jsx:encode([]), Req, State}
  end.
  
