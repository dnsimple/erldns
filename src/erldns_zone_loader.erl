%% Copyright (c) 2012-2020, DNSimple Corporation
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

%% @doc Funcions for loading zones from local or remote sources.
-module(erldns_zone_loader).

-export([load_zones/0]).

-define(FILENAME, "zones.json").

-ifdef(TEST).

-include_lib("eunit/include/eunit.hrl").

-endif.

% Public API

%% @doc Load zones from a file. The default file name is "zones.json".
-spec load_zones() -> {ok, integer()} | {err, atom()}.
load_zones() ->
    case file:read_file(filename()) of
        {ok, Binary} ->
            lager:info("Parsing zones JSON"),
            JsonZones = jsx:decode(Binary, [{return_maps, false}]),
            lager:info("Putting zones into cache"),
            lists:foreach(fun(JsonZone) ->
                             Zone = erldns_zone_parser:zone_to_erlang(JsonZone),
                             case erldns_zone_cache:put_zone(Zone) of
                                 {error, Reason} -> erldns_events:notify({?MODULE, put_zone_error, {JsonZone, Reason}});
                                 _ -> ok
                             end
                          end,
                          JsonZones),
            lager:info("Loaded zones (count: ~p)", [length(JsonZones)]),
            {ok, length(JsonZones)};
        {error, Reason} ->
            erldns_events:notify({?MODULE, read_file_error, Reason}),
            {err, Reason}
    end.

% Internal API
filename() ->
    case application:get_env(erldns, zones) of
        {ok, Filename} ->
            Filename;
        _ ->
            ?FILENAME
    end.

-ifdef(TEST).

json_jsx_decode_test() ->
    Zone_RR =
        [{<<"name">>, <<"example.net">>},
         {<<"records">>,
          [[{<<"name">>, <<"example.net">>},
            {<<"type">>, <<"SOA">>},
            {<<"ttl">>, 3600},
            {<<"data">>,
             [{<<"mname">>, <<"ns1.example.net">>},
              {<<"rname">>, <<"admin.example.net">>},
              {<<"serial">>, 1234567},
              {<<"refresh">>, 1},
              {<<"retry">>, 1},
              {<<"expire">>, 1},
              {<<"minimum">>, 1}]}],
           [{<<"name">>, <<"ns1.example.net">>}, {<<"type">>, <<"A">>}, {<<"ttl">>, 30}, {<<"data">>, [{<<"ip">>, <<"123.45.67.89">>}]}]]}],
    JSON_zone =
        <<"{\"name\":\"example.net\",\"records\":[{\"name\":\"example.net\",\"type\":\"SOA\",\"ttl\":3600,\"data\":{\"m"
          "name\":\"ns1.example.net\",\"rname\":\"admin.example.net\",\"serial\":1234567,\"refresh\":1,\"retry\":1,\"ex"
          "pire\":1,\"minimum\":1}},{\"name\":\"ns1.example.net\",\"type\":\"A\",\"ttl\":30,\"data\":{\"ip\":\"123.45.6"
          "7.89\"}}]}">>,
    ?assertEqual(Zone_RR, jsx:decode(JSON_zone, [{return_maps, false}])).

-endif.
