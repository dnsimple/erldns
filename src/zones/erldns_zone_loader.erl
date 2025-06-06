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
See the type `t:config/0` for details.
""".

-include_lib("kernel/include/logger.hrl").

-doc """
Zone loader configuration.

Path can be a directory, and `strict` declares whether load failure should crash or be ignored.
""".
-type config() :: #{
    path => file:name(),
    strict => boolean()
}.

-behaviour(gen_server).
-export([load_zones/0, load_zones/1]).
-export([start_link/0, init/1, handle_call/3, handle_cast/2]).

-define(PATH, "zones.json").

-doc "Load zones.".
-spec load_zones() -> non_neg_integer().
load_zones() ->
    ?LOG_INFO(#{what => loading_zones_from_local_file}),
    Config = get_config(),
    load_zones(Config).

-doc """
Load zones from a file in strict or loose mode.
""".
-spec load_zones(config()) -> non_neg_integer().
load_zones(#{path := Path, strict := Strictness}) ->
    load_zones(Strictness, Path).

-spec load_zones(boolean(), file:name()) -> non_neg_integer().
load_zones(Strictness, Path) when is_boolean(Strictness), is_list(Path) ->
    case filelib:is_dir(Path) of
        true ->
            ZoneFiles = filelib:wildcard(filename:join([Path, "*.json"])),
            load_zone_files_parallel(Strictness, ZoneFiles, length(ZoneFiles));
        false ->
            load_zone_files_parallel(Strictness, [Path], 1)
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
    end.

zone_loader(Ref, ParentPid) ->
    receive
        {Ref, JsonZone, load} ->
            load_zone(JsonZone),
            ParentPid ! {Ref, 1},
            zone_loader(Ref, ParentPid);
        {Ref, ParentPid, stop} ->
            ok
    end.

load_zone(JsonZone) ->
    Zone = erldns_zone_parser:zone_to_erlang(JsonZone),
    erldns_zone_cache:put_zone(Zone).

% Internal API
get_config() ->
    case application:get_env(erldns, zones, default_config()) of
        #{path := Path, strict := Strictness} = Config when
            is_list(Path), is_boolean(Strictness)
        ->
            Config;
        #{strict := Strictness} = Config when
            is_boolean(Strictness)
        ->
            Config#{path => ?PATH};
        #{path := Path} = Config when
            is_list(Path)
        ->
            Config#{strict => true};
        Other ->
            erlang:error({badconfig, Other})
    end.

-spec default_config() -> config().
default_config() ->
    #{path => ?PATH, strict => true}.

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
    ?LOG_INFO(#{what => unexpected_call, from => From, call => Call}),
    {reply, not_implemented, State}.

-doc false.
-spec handle_cast(dynamic(), nostate) -> {noreply, nostate}.
handle_cast(Cast, State) ->
    ?LOG_INFO(#{what => unexpected_cast, cast => Cast}),
    {noreply, State}.
