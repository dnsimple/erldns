-module(erldns_zone_loader_worker).
-moduledoc false.

-include_lib("dns_erlang/include/dns.hrl").

-export([load_file/3, start_link/3, init/3]).

-spec load_file(gen_server:from(), file:filename(), boolean()) -> supervisor:startlink_ret().
load_file(Tag, File, Strict) ->
    erldns_zone_loader_worker_sup:start_child([Tag, File, Strict]).

-spec start_link(erldns_zone_loader_getter:tag(), file:filename(), boolean()) -> dynamic().
start_link(Tag, File, Strict) ->
    proc_lib:start_link(?MODULE, init, [Tag, File, Strict]).

-spec init(erldns_zone_loader_getter:tag(), file:filename(), boolean()) -> no_return().
init(Tag, File, Strict) ->
    Self = self(),
    proc_lib:init_ack({ok, Self}),
    run(Tag, File, Strict, Self).

run(Tag, File, Strict, Self) ->
    try
        Zones = do_load_file(File, Strict),
        lists:map(fun erldns_zone_cache:put_zone/1, Zones),
        erldns_zone_loader_getter:respond(Tag, Self, {ok, length(Zones)})
    catch
        error:Reason ->
            erldns_zone_loader_getter:respond(Tag, Self, {error, Reason}),
            {error, Reason}
    end.

-spec do_load_file(file:filename(), boolean()) -> [erldns:zone()].
do_load_file(File, Strict) ->
    case filename:extension(File) of
        ".json" ->
            load_json_file(File, Strict);
        ".zone" ->
            load_zone_file(File, Strict)
    end.

-spec load_json_file(file:filename(), boolean()) -> [erldns:zone()].
load_json_file(File, Strict) ->
    maybe
        {ok, Content} ?= file:read_file(File, [raw]),
        {ok, Zones} ?= safe_json_zones_decode(Content, Strict, File),
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
            Strict andalso erlang:error({json_error, Reason}),
            []
    end.

-spec ensure_zones([json:decode_value()], boolean()) -> [json:decode_value()] | no_return().
ensure_zones([#{~"name" := _, ~"records" := _} = H | T], Strict) ->
    [H | ensure_zones(T, Strict)];
ensure_zones([_ | T], Strict) ->
    Strict andalso erlang:error(invalid_zone_file),
    ensure_zones(T, Strict);
ensure_zones([], _) ->
    [].

-spec load_zone_file(file:filename(), boolean()) -> [erldns:zone()].
load_zone_file(File, Strict) ->
    maybe
        {ok, Records0} ?= dns_zone:parse_file(File),
        Records = parse_zonefile_records(Records0, Strict),
        Soa = #dns_rr{name = Name} ?= lists:keyfind(?DNS_TYPE_SOA, #dns_rr.type, Records),
        Sha = crypto:hash(sha256, term_to_binary(Soa)),
        [erldns_zone_codec:build_zone(Name, Sha, Records, [])]
    else
        false ->
            Strict andalso erlang:error({invalid_zone_file, File}),
            [];
        {error, Reason} ->
            Strict andalso erlang:error({file_read_error, File, Reason}),
            []
    end.

-spec parse_zonefile_records([dns:rr()], boolean()) -> [dns:rr()].
parse_zonefile_records(Records, Strict) ->
    lists:map(fun(Record) -> parse_zonefile_record(Record, Strict) end, Records).

-spec parse_zonefile_record(dns:rr(), boolean()) -> dns:rr().
parse_zonefile_record(#dns_rr{data = Data} = Record, Strict) when is_binary(Data) ->
    maybe
        {ok, Json} ?= safe_json_record_decode(Data),
        #dns_rr{} ?= erldns_zone_codec:decode_record(Json)
    else
        not_implemented ->
            Strict andalso erlang:error({custom_record_could_not_be_decoded, Record}),
            Record;
        {json_error, Reason} ->
            Strict andalso erlang:error(Reason),
            Record
    end;
parse_zonefile_record(Record, _) ->
    Record.

-spec safe_json_record_decode(binary()) -> {ok, json:decode_value()} | {json_error, dynamic()}.
safe_json_record_decode(Binary) ->
    try json:decode(Binary) of
        Map when is_map(Map) ->
            {ok, Map};
        _ ->
            {json_error, invalid_record}
    catch
        error:Reason -> {json_error, Reason}
    end.
