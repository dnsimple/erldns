-module(erldns_zone_loader).

-export([load_zones/0]).

-define(FILENAME, "zones.json").

load_zones() ->
  case file:read_file(?FILENAME) of
    {ok, Binary} ->
      Zones = erldns_zone_parser:zones_to_erlang(jsx:decode(Binary)),
      lists:foreach(
        fun(Zone) ->
            erldns_zone_cache:put_zone(Zone)
        end, Zones),
      lager:info("Loaded ~p zones", [length(Zones)]),
      {ok, length(Zones)};
    {error, Reason} ->
      lager:error("Failed to load zones: ~p", [Reason]),
      {err, Reason}
  end.
