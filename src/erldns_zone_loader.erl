-module(erldns_zone_loader).

-export([load_zones/0]).

-define(FILENAME, "zones.json").

load_zones() ->
  case file:read_file(filename()) of
    {ok, Binary} ->
      lager:info("Parsing zones JSON"),
      JsonZones = jsx:decode(Binary),
      lager:info("Putting zones into cache"),
      lists:foreach(
        fun(JsonZone) ->
            Zone = erldns_zone_parser:zone_to_erlang(JsonZone),
            erldns_zone_cache:put_zone(Zone)
        end, JsonZones),
      lager:info("Loaded ~p zones", [length(JsonZones)]),
      {ok, length(JsonZones)};
    {error, Reason} ->
      lager:error("Failed to load zones: ~p", [Reason]),
      {err, Reason}
  end.

filename() ->
  case application:get_env(erldns, zones) of
    {ok, Filename} -> Filename;
    _ -> ?FILENAME
  end.
