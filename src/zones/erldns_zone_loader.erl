-module(erldns_zone_loader).
-moduledoc """
Functions for loading zones from local or remote sources.

## Configuration
```erlang
{erldns, [
    {zones, #{
        path => "zones.json",
        strict => true
    }
]}
```
See the type `t:erldns_zones:config/0` for details.
""".

-include_lib("kernel/include/logger.hrl").

-define(WILDCARD, "**/*.json").
-define(TIMEOUT, timer:minutes(30)).

-behaviour(gen_server).
-export([load_zones/0, load_zones/1]).
-export([start_link/0, init/1, handle_call/3, handle_cast/2]).

-doc "Load zones.".
-spec load_zones() -> non_neg_integer().
load_zones() ->
    Count =
        case get_config() of
            #{path := Path, strict := Strict} ->
                ?LOG_INFO(
                    #{what => loading_zones_from_local_files, path => Path, strict => Strict}, #{
                        domain => [erldns, zones]
                    }
                ),
                load_zones(Strict, Path);
            _ ->
                0
        end,
    ?LOG_INFO(
        #{what => loaded_zones_from_local_files, zone_count => Count},
        #{domain => [erldns, zones]}
    ),
    Count.

-doc """
Load zones from a file in strict or loose mode.
""".
-spec load_zones(file:name()) -> non_neg_integer().
load_zones(Path) ->
    fail_if_strict_and_path_not_found(true, Path, #{}),
    load_zones(true, Path).

-spec load_zones(boolean(), file:name()) -> non_neg_integer().
load_zones(Strict, Path) when is_boolean(Strict), is_list(Path) ->
    case filelib:is_dir(Path) of
        true ->
            ZoneFiles = filelib:wildcard(filename:join([Path, ?WILDCARD])),
            load_zone_files_parallel(Strict, ZoneFiles, length(ZoneFiles));
        false ->
            load_zone_files_parallel(Strict, [Path], 1)
    end.

load_zone_files_parallel(Strict, ZoneFileNames, _ZoneFilesCount) ->
    Ref = make_ref(),
    ParentPid = self(),
    {LoaderPids, LoaderMons} = create_loaders(Ref, ParentPid),
    {ParserPid, ParserMon} = spawn_monitor(
        fun() -> zone_parser(Ref, ParentPid, LoaderPids, Strict) end
    ),
    {ReaderPid, ReaderMon} = spawn_monitor(
        fun() -> zone_reader(Ref, ParentPid, ParserPid, Strict) end
    ),
    [ReaderPid ! {Ref, Filename, read} || Filename <- ZoneFileNames],
    ReaderPid ! {Ref, ParentPid, stop},
    case if_any_died(Ref, [ParserPid, ReaderPid | LoaderPids], LoaderMons, ReaderMon, ParserMon) of
        {ok, Count} ->
            Count;
        {error, Reason} ->
            erlang:error(Reason)
    end.

create_loaders(Ref, ParentPid) ->
    Spawns = [
        spawn_monitor(
            fun() -> zone_loader(Ref, ParentPid) end
        )
     || _ <- lists:seq(1, erlang:system_info(schedulers))
    ],
    lists:unzip(Spawns).

if_any_died(Ref, _, [], undefined, undefined) ->
    count_zones(Ref, 0);
if_any_died(Ref, Pids, LoaderMons, ReaderMon, ParserMon) ->
    receive
        {'DOWN', ReaderMon, process, _, normal} ->
            if_any_died(Ref, Pids, LoaderMons, undefined, ParserMon);
        {'DOWN', ParserMon, process, _, normal} ->
            if_any_died(Ref, Pids, LoaderMons, ReaderMon, undefined);
        {'DOWN', LoaderMon, process, _, normal} ->
            if_any_died(Ref, Pids, lists:delete(LoaderMon, LoaderMons), ReaderMon, ParserMon);
        {'DOWN', ReaderMon, process, _, Reason} when normal =/= Reason ->
            [exit(Pid, kill) || Pid <- Pids],
            {error, Reason};
        {'DOWN', ParserMon, process, _, Reason} when normal =/= Reason ->
            [exit(Pid, kill) || Pid <- Pids],
            {error, Reason};
        {'DOWN', _LoaderMon, process, _, Reason} when normal =/= Reason ->
            [exit(Pid, kill) || Pid <- Pids],
            {error, Reason}
    after ?TIMEOUT ->
        ok
    end.

count_zones(Ref, Count) ->
    receive
        {Ref, N} ->
            count_zones(Ref, Count + N)
    after 0 ->
        {ok, Count}
    end.

zone_reader(Ref, ParentPid, ParserPid, Strict) ->
    receive
        {Ref, Filename, read} ->
            case file:read_file(Filename) of
                {ok, FileContent} ->
                    ParserPid ! {Ref, FileContent, parse},
                    zone_reader(Ref, ParentPid, ParserPid, Strict);
                {error, Reason} ->
                    case Strict of
                        true ->
                            exit(Reason);
                        false ->
                            zone_reader(Ref, ParentPid, ParserPid, Strict)
                    end
            end;
        {Ref, ParentPid, stop} ->
            ParserPid ! {Ref, ParentPid, stop},
            ok
    after ?TIMEOUT ->
        ok
    end.

zone_parser(Ref, ParentPid, LoaderPids, Strict) ->
    receive
        {Ref, FileContent, parse} ->
            case safe_json_decode(FileContent) of
                {ok, JsonZones} ->
                    [
                        lists:nth(rand:uniform(length(LoaderPids)), LoaderPids) !
                            {Ref, JsonZone, load}
                     || JsonZone <- JsonZones
                    ],
                    zone_parser(Ref, ParentPid, LoaderPids, Strict);
                {error, Reason} ->
                    case Strict of
                        true ->
                            exit(Reason);
                        false ->
                            zone_parser(Ref, ParentPid, LoaderPids, Strict)
                    end
            end;
        {Ref, ParentPid, stop} ->
            [LoaderPid ! {Ref, ParentPid, stop} || LoaderPid <- LoaderPids],
            ok
    after ?TIMEOUT ->
        ok
    end.

zone_loader(Ref, ParentPid) ->
    receive
        {Ref, JsonZone, load} ->
            load_zone(JsonZone),
            ParentPid ! {Ref, 1},
            zone_loader(Ref, ParentPid);
        {Ref, ParentPid, stop} ->
            ok
    after ?TIMEOUT ->
        ok
    end.

load_zone(JsonZone) ->
    Zone = erldns_zone_codec:decode(JsonZone),
    erldns_zone_cache:put_zone(Zone).

% Internal API
-spec get_config() -> erldns_zones:config().
get_config() ->
    case application:get_env(erldns, zones, #{}) of
        #{strict := Strict} when not is_boolean(Strict) ->
            erlang:error({badconfig, invalid_strict_value});
        #{path := Path, strict := false} = Config when is_list(Path) ->
            fail_if_strict_and_path_not_found(false, Path, Config);
        #{path := Path, strict := true} = Config when is_list(Path) ->
            fail_if_strict_and_path_not_found(true, Path, Config);
        #{path := Path} = Config ->
            fail_if_strict_and_path_not_found(true, Path, Config#{strict => true});
        #{strict := true} ->
            erlang:error({badconfig, enoent});
        #{strict := false} = Config ->
            Config;
        Other ->
            Other
    end.

fail_if_strict_and_path_not_found(true, Path, Config) ->
    case filelib:is_dir(Path) orelse filelib:is_file(Path) of
        true ->
            Config;
        false ->
            erlang:error({badconfig, enoent})
    end;
fail_if_strict_and_path_not_found(false, _, Config) ->
    Config.

safe_json_decode(Binary) ->
    try json:decode(Binary) of
        List when is_list(List) ->
            {ok, List};
        _ ->
            {error, invalid_zone_file}
    catch
        error:Reason -> {error, Reason}
    end.

-doc false.
-spec start_link() -> term().
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, noargs, [{hibernate_after, 0}]).

-doc false.
-spec init(noargs) -> {ok, nostate}.
init(noargs) ->
    load_zones(),
    {ok, nostate}.

-doc false.
-spec handle_call(dynamic(), gen_server:from(), nostate) ->
    {reply, not_implemented, nostate}.
handle_call(Call, From, State) ->
    ?LOG_INFO(#{what => unexpected_call, from => From, call => Call}, #{domain => [erldns, zones]}),
    {reply, not_implemented, State}.

-doc false.
-spec handle_cast(dynamic(), nostate) -> {noreply, nostate}.
handle_cast(Cast, State) ->
    ?LOG_INFO(#{what => unexpected_cast, cast => Cast}, #{domain => [erldns, zones]}),
    {noreply, State}.
