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

-include_lib("dns/include/dns.hrl").
-include("erldns.hrl").

% Public API
-export([
    fetch_zones/0,
    fetch_zones/1,
    fetch_zone/1,
    fetch_zone/2,
    do_fetch_zone/2
  ]).

-define(PARALLEL_ZONE_LOADING, true).

% Public API
fetch_zones() ->
  fetch_zones(?PARALLEL_ZONE_LOADING).

fetch_zones(Parallel) ->
  case httpc:request(get, {zones_url(), headers()}, [], [{body_format, binary}]) of
    {ok, {{_Version, 200, _ReasonPhrase}, _Headers, Body}} ->
      JsonZones = jsx:decode(Body),
      erldns_zone_fetcher_countdown:set_remaining(length(JsonZones)),
      lager:info("Putting zones into cache"),
      lists:foreach(
        fun([{<<"name">>, Name}, {<<"sha">>, Sha}, _]) ->
            case Parallel of
              true ->
                lager:debug("Fetch zone ~p, ~p", [Name, Sha]),
                hottub:cast(zone_fetcher, {fetch_zone, Name, Sha});
              _ ->
                fetch_zone(Name, Sha)
            end
        end, JsonZones),
      lager:debug("Zone fetchers are all running, leaving fetch_zones()"),
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
  AuthHeader = auth_header(),
  lager:debug("do_fetch_zone(~p, ~p)", [Name, Url]),
  case httpc:request(get, {Url, [AuthHeader]}, [], [{body_format, binary}]) of
    {ok, {{_Version, 200, _ReasonPhrase}, _Headers, Body}} ->
      lager:debug("Zone fetched: ~p", [Name]),
      safe_process_json_zone(jsx:decode(Body), 'cast');
    {_, {{_Version, Status = 304, ReasonPhrase}, _Headers, _Body}} ->
      lager:debug("Zone not modified: ~p", [Name]),
      {ok, Status, ReasonPhrase};
    {_, {{_Version, Status = 404, ReasonPhrase}, _Headers, _Body}} ->
      lager:debug("Zone not found: ~p", [Name]),
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

%% Internal functions

zones_url() ->
  erldns_config:zone_server_protocol() ++ "://" ++ erldns_config:zone_server_host() ++ ":" ++ integer_to_list(erldns_config:zone_server_port()) ++ "/zones/".

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
