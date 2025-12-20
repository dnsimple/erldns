#!/usr/bin/env escript
%% -*- erlang -*-

-export([main/1]).

main([ZonesDir]) ->
    {ok, Files} = file:list_dir(ZonesDir),
    JsonFiles = [filename:join(ZonesDir, F) || F <- Files, filename:extension(F) == ".json"],
    io:format("Processing ~p zone files...~n", [length(JsonFiles)]),
    {ok, Out} = file:open("queries.txt", [write, raw, binary, delayed_write]),
    lists:foreach(fun(File) -> process_file(File, Out) end, JsonFiles),
    file:close(Out),
    io:format("Generated queries.txt successfully.~n");
main(_) ->
    io:format("Usage: ./gen_queries.erl <path_to_zones_dir>~n").

process_file(Path, Out) ->
    {ok, Binary} = file:read_file(Path, [raw]),
    Zones = json:decode(Binary),
    lists:foreach(
        fun(Zone) ->
            Records = maps:get(~"records", Zone),
            lists:foreach(
                fun(Rec) ->
                    Name = maps:get(~"name", Rec),
                    Type = maps:get(~"type", Rec),
                    %% kxdpgun format: name type flags
                    Line = <<Name/binary, " ", Type/binary, " DE\n">>,
                    file:write(Out, Line)
                end,
                Records
            )
        end,
        Zones
    ).
