-module(erldns_zone_loader_worker).
-moduledoc false.

-include_lib("dns_erlang/include/dns.hrl").

-export([load_file/4, start_link/4, init/4]).

-spec load_file(gen_server:from(), file:filename(), file:name(), boolean()) ->
    supervisor:startlink_ret().
load_file(Tag, File, KeysPath, Strict) ->
    erldns_zone_loader_worker_sup:start_child([Tag, File, KeysPath, Strict]).

-spec start_link(erldns_zone_loader_getter:tag(), file:filename(), file:name(), boolean()) ->
    dynamic().
start_link(Tag, File, KeysPath, Strict) ->
    proc_lib:start_link(?MODULE, init, [Tag, File, KeysPath, Strict]).

-spec init(erldns_zone_loader_getter:tag(), file:filename(), file:name(), boolean()) -> no_return().
init(Tag, File, KeysPath, Strict) ->
    Self = self(),
    proc_lib:init_ack({ok, Self}),
    run(Tag, File, KeysPath, Strict, Self).

run(Tag, File, KeysPath, Strict, Self) ->
    try
        Zones = do_load_file(File, KeysPath, Strict),
        lists:map(fun erldns_zone_cache:put_zone/1, Zones),
        erldns_zone_loader_getter:respond(Tag, Self, {ok, length(Zones)})
    catch
        throw:Reason ->
            erldns_zone_loader_getter:respond(Tag, Self, {error, Reason});
        error:unexpected_end = Error ->
            erldns_zone_loader_getter:respond(Tag, Self, {error, {json_error, Error}});
        error:{invalid_byte, _} = Error ->
            erldns_zone_loader_getter:respond(Tag, Self, {error, {json_error, Error}});
        error:{unexpected_sequence, _} = Error ->
            erldns_zone_loader_getter:respond(Tag, Self, {error, {json_error, Error}});
        error:Reason:StackTrace ->
            erldns_zone_loader_getter:respond(Tag, Self, {error, {Reason, StackTrace}})
    end.

-spec do_load_file(file:filename(), file:name(), boolean()) -> [erldns:zone()].
do_load_file(File, KeysPath, Strict) ->
    case filename:extension(File) of
        ".json" ->
            load_json_file(File, Strict);
        ".zone" ->
            load_zone_file(File, KeysPath, Strict)
    end.

-spec load_json_file(file:filename(), boolean()) -> [erldns:zone()].
load_json_file(File, Strict) ->
    maybe
        {ok, Content} ?= file:read_file(File, [raw]),
        {ok, List} ?= safe_json_decode_list(Content),
        Zones = ensure_zones(List, Strict),
        [erldns_zone_codec:decode(Zone) || Zone <- Zones]
    else
        [] ->
            [];
        {json_error, Reason} ->
            Strict andalso erlang:throw({invalid_zone_file, Reason}),
            [];
        {error, Reason} ->
            Strict andalso erlang:throw({file_read_error, File, Reason}),
            []
    end.

-spec ensure_zones([json:decode_value()], boolean()) -> [json:decode_value()] | no_return().
ensure_zones([#{~"name" := _, ~"records" := _} = H | T], Strict) ->
    [H | ensure_zones(T, Strict)];
ensure_zones([_ | T], Strict) ->
    Strict andalso erlang:throw(invalid_zone_file),
    ensure_zones(T, Strict);
ensure_zones([], _) ->
    [].

-spec load_zone_file(file:filename(), file:name(), boolean()) -> [erldns:zone()].
load_zone_file(File, KeysPath, Strict) ->
    maybe
        {ok, Records0} ?= dns_zone:parse_file(File),
        Records = parse_zonefile_records(Records0, Strict),
        Soa = #dns_rr{name = ZoneName} ?= lists:keyfind(?DNS_TYPE_SOA, #dns_rr.type, Records),
        Sha = crypto:hash(sha256, term_to_binary(Soa)),
        Keys = load_private_keys(ZoneName, KeysPath),
        [erldns_zone_codec:build_zone(ZoneName, Sha, Records, Keys)]
    else
        false ->
            Strict andalso erlang:throw({invalid_zone_file, File}),
            [];
        {error, Reason} ->
            Strict andalso erlang:throw({file_read_error, File, Reason}),
            []
    end.

%% Finds and loads private keys for every DNSKEY record in the list.
-spec load_private_keys(dns:dname(), file:name()) -> [erldns:keyset()].
load_private_keys(ZoneName, KeysDir) ->
    Trimmed = string:trim(ZoneName, trailing, "."),
    FileName = <<Trimmed/binary, ".private">>,
    FullPath = filename:join(KeysDir, FileName),
    maybe
        {ok, Content} ?= file:read_file(FullPath, [raw]),
        {ok, Json} ?= safe_json_decode_list(Content),
        erldns_zone_decoder:parse_keysets(Json)
    else
        {json_error, Reason} ->
            erlang:throw({invalid_key_file, FullPath, Reason});
        {error, _} ->
            %% File not found - This is normal for public keys we don't own
            %% (or if we only have the ZSK but the KSK is held offline)
            []
    end.

-spec parse_zonefile_records([dns:rr()], boolean()) -> [dns:rr()].
parse_zonefile_records(Records, Strict) ->
    lists:map(fun(Record) -> parse_zonefile_record(Record, Strict) end, Records).

%% Parses a JSON map (from a key file) into an Erlang crypto key record.
-spec parse_zonefile_record(dns:rr(), boolean()) -> dns:rr().
parse_zonefile_record(#dns_rr{data = Data} = Record, Strict) when is_binary(Data) ->
    maybe
        {ok, Json} ?= safe_json_decode_record(Data),
        #dns_rr{} ?= erldns_zone_codec:decode_record(Json)
    else
        not_implemented ->
            Strict andalso erlang:throw({custom_record_could_not_be_decoded, Record}),
            Record;
        {json_error, Reason} ->
            Strict andalso erlang:throw(Reason),
            Record
    end;
parse_zonefile_record(Record, _) ->
    Record.

-spec safe_json_decode_list(binary()) -> {ok, [json:decode_value()]} | {json_error, atom()}.
safe_json_decode_list(Binary) ->
    case json:decode(Binary) of
        List when is_list(List) ->
            {ok, List};
        _ ->
            {json_error, invalid_zone_file}
    end.

-spec safe_json_decode_record(binary()) -> {ok, json:decode_value()} | {json_error, atom()}.
safe_json_decode_record(Binary) ->
    case json:decode(Binary) of
        Map when is_map(Map) ->
            {ok, Map};
        _ ->
            {json_error, invalid_record}
    end.
