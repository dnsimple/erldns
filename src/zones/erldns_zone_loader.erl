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
-include_lib("dns_erlang/include/dns.hrl").

-define(LOG_METADATA, #{domain => [erldns, zones]}).
-define(WILDCARD_JSON, "**/*.json").
-define(WILDCARD_ZONE, "**/*.zone").
-define(WILDCARD_AUTO, "**/*.{json,zone}").
-define(TIMEOUT, timer:minutes(30)).

-behaviour(gen_server).
-export([load_zones/0, load_zones/1]).
-export([start_link/0, init/1, handle_call/3, handle_cast/2]).

-doc "Load zones.".
-spec load_zones() -> {non_neg_integer(), [erldns:zone()]}.
load_zones() ->
    {Count, Res} = load_and_get_count(),
    ?LOG_INFO(#{what => loaded_zones_from_local_files, zone_count => Count}, ?LOG_METADATA),
    {Count, Res}.

-doc "Load zones from a given configuration, see `t:erldns_zones:config/0` for details.".
-spec load_zones(erldns_zones:config() | file:name()) -> {non_neg_integer(), [erldns:zone()]}.
load_zones(Path) when is_list(Path) ->
    load_and_get_count(#{path => Path});
load_zones(Config) when is_map(Config) ->
    load_and_get_count(get_config(Config)).

-spec load_and_get_count() -> {non_neg_integer(), [erldns:zone()]}.
load_and_get_count() ->
    load_and_get_count(get_config()).

-spec load_and_get_count(erldns_zones:config()) -> {non_neg_integer(), [erldns:zone()]}.
load_and_get_count(Config) ->
    case Config of
        #{path := Path, strict := Strict, format := Format, timeout := Timeout} ->
            ?LOG_INFO(
                #{
                    what => loading_zones_from_local_files,
                    path => Path,
                    format => Format,
                    strict => Strict
                },
                ?LOG_METADATA
            ),
            do_load_zones(Path, Format, Timeout, Strict);
        _ ->
            {0, []}
    end.

-spec do_load_zones(file:name(), erldns_zones:format(), timeout(), boolean()) ->
    {non_neg_integer(), [erldns:zone()]}.
do_load_zones(Path, Format, _Timeout, Strict) ->
    Files = find_zone_files(Path, Format),
    Zones = lists:flatten([load_file(File, Strict) || File <- Files]),
    Count = lists:flatten([load_zone(Zone) || Zone <- Zones]),
    {length(Count), Zones}.

-spec find_zone_files(file:name(), erldns_zones:format()) -> [file:filename()].
find_zone_files(Path, Format) ->
    case {filelib:is_dir(Path), Format} of
        {false, _} ->
            [Path];
        {true, json} ->
            filelib:wildcard(filename:join([Path, ?WILDCARD_JSON]), prim_file);
        {true, zonefile} ->
            filelib:wildcard(filename:join([Path, ?WILDCARD_ZONE]), prim_file);
        {true, auto} ->
            filelib:wildcard(filename:join([Path, ?WILDCARD_AUTO]), prim_file)
    end.

-spec load_file(file:filename(), boolean()) -> [erldns:zone()].
load_file(File, Strict) ->
    case filename:extension(File) of
        ".json" ->
            load_json_file(File, Strict);
        ".zone" ->
            load_zone_file(File, Strict);
        _ ->
            Strict andalso erlang:error({unsupported_file_extension, File}),
            []
    end.

-spec load_json_file(file:filename(), boolean()) -> [erldns:zone()].
load_json_file(File, Strict) ->
    maybe
        {ok, Content} ?= file:read_file(File, [raw]),
        {ok, Zones} ?= safe_json_zones_decode(Content, Strict, File),
        ct:pal("~p", [{File, Strict, Zones}]),
        [erldns_zone_codec:decode(Zone) || Zone <- Zones]
    else
        [] ->
            [];
        {error, Reason} ->
            Strict andalso erlang:error({file_read_error, File, Reason}),
            []
    end.

-spec safe_json_zones_decode(binary(), boolean(), file:filename()) ->
    {ok, [json:decode_value()]} | {json_error, term()}.
safe_json_zones_decode(Binary, Strict, File) ->
    try json:decode(Binary) of
        List when is_list(List) ->
            {ok, ensure_zones(List, Strict)};
        _ ->
            Strict andalso erlang:error({invalid_zone_file, File}),
            []
    catch
        error:Reason ->
            Strict andalso erlang:error(Reason),
            []
    end.

-spec ensure_zones([json:decode_value()], boolean()) -> [json:decode_value()].
ensure_zones([#{~"name" := _, ~"records" := _} = H | T], Strict) ->
    [H | ensure_zones(T, Strict)];
ensure_zones([_ | T], Strict) ->
    Strict andalso erlang:error({json_error, invalid_zone_file}),
    ensure_zones(T, Strict);
ensure_zones([], _) ->
    [].

-spec safe_json_record_decode(binary()) ->
    {ok, json:decode_value()} | {error, invalid_zone_file} | {json_error, term()}.
safe_json_record_decode(Binary) ->
    try json:decode(Binary) of
        Map when is_map(Map) ->
            {ok, Map};
        _ ->
            {error, {json_error, invalid_record}}
    catch
        error:Reason -> {json_error, Reason}
    end.

-spec load_zone_file(file:filename(), boolean()) -> [erldns:zone()].
load_zone_file(File, Strict) ->
    maybe
        {ok, Records0} ?= dns_zone:parse_file(File),
        Records = parse_zonefile_records(Records0, Strict),
        Soa = #dns_rr{name = Name} ?= lists:keyfind(?DNS_TYPE_SOA, #dns_rr.type, Records),
        Sha = crypto:hash(sha256, term_to_binary(Soa)),
        erldns_zone_codec:build_zone(Name, Sha, Records, [])
    else
        false ->
            Strict andalso erlang:error({invalid_zone_file, File}),
            [];
        {error, Reason} ->
            Strict andalso erlang:error({file_read_error, File, Reason}),
            []
    end.

parse_zonefile_records(Records, Strict) ->
    lists:map(fun(Record) -> parse_zonefile_record(Record, Strict) end, Records).

parse_zonefile_record(#dns_rr{data = Data} = Record, Strict) when is_binary(Data) ->
    maybe
        {ok, Json} ?= safe_json_record_decode(Data),
        DnsRr = #dns_rr{} ?= erldns_zone_codec:decode_record(Json),
        ct:pal("~p", [Json]),
        DnsRr
    else
        not_implemented ->
            Strict andalso erlang:error({custom_record_could_not_be_decoded, Record}),
            Record;
        {json_error, _Reason} ->
            % Strict andalso erlang:error(Reason),
            Record
    end;
parse_zonefile_record(Record, _) ->
    Record.

-spec load_zone(dynamic()) -> ok.
load_zone(Zone) ->
    erldns_zone_cache:put_zone(Zone).

% Internal API
-spec get_config() -> erldns_zones:config().
get_config() ->
    Config = application:get_env(erldns, zones, #{}),
    get_config(Config).

get_config(Config) ->
    Format = maps:get(format, Config, json),
    Timeout = maps:get(timeout, Config, ?TIMEOUT),
    Path = maps:get(path, Config, undefined),
    Strict = maps:get(strict, Config, undefined =/= Path),
    assert_valid_format(Format),
    assert_valid_timeout(Timeout),
    assert_valid_path(Path, Strict),
    case Path of
        undefined ->
            #{};
        _ ->
            #{path => Path, strict => Strict, format => Format, timeout => Timeout}
    end.

-spec assert_valid_format(erldns_zones:format()) -> ok | no_return().
assert_valid_format(Format) ->
    Format =:= json orelse Format =:= zonefile orelse Format =:= auto orelse
        erlang:error({badconfig, invalid_format_value}).

-spec assert_valid_timeout(timeout()) -> ok | no_return().
assert_valid_timeout(Timeout) ->
    (is_integer(Timeout) andalso Timeout > 0) orelse infinity =:= Timeout orelse
        erlang:error({badconfig, invalid_timeout_value}).

-spec assert_valid_path(file:name() | undefined, boolean()) -> ok | no_return().
assert_valid_path(_, Strict) when not is_boolean(Strict) ->
    erlang:error({badconfig, invalid_strict_value});
assert_valid_path(Path, Strict) when is_list(Path) ->
    fail_if_strict_and_path_not_found(Path, Strict);
assert_valid_path(_, true) ->
    erlang:error({badconfig, enoent});
assert_valid_path(undefined, _) ->
    undefined;
assert_valid_path(_, _) ->
    undefined.

-spec fail_if_strict_and_path_not_found(file:name(), boolean()) -> ok | no_return().
fail_if_strict_and_path_not_found(Path, Strict) ->
    case not Strict orelse filelib:is_dir(Path) orelse filelib:is_file(Path) of
        true ->
            ok;
        false ->
            erlang:error({badconfig, enoent})
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
    ?LOG_INFO(#{what => unexpected_call, from => From, call => Call}, ?LOG_METADATA),
    {reply, not_implemented, State}.

-doc false.
-spec handle_cast(dynamic(), nostate) -> {noreply, nostate}.
handle_cast(Cast, State) ->
    ?LOG_INFO(#{what => unexpected_cast, cast => Cast}, ?LOG_METADATA),
    {noreply, State}.
