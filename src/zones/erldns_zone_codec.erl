-module(erldns_zone_codec).
-moduledoc """
Encoding and decoding of zone data in JSON format.

Zones are decoded through `m:erldns_zone_pipeline`, whose pipes also decode the records of the
types erldns doesn't know, and encode them back.
""".

-behaviour(gen_server).

-include_lib("kernel/include/logger.hrl").
-include_lib("erldns/include/erldns.hrl").

-export([build_zone/4, encode/1, encode/2, decode/1, decode/2, decode_records/2]).

-export([start_link/0, init/1, handle_call/3, handle_cast/2, terminate/2]).

-type state() :: nostate.
-export_type([state/0]).

-spec build_zone(dns:dname(), binary(), [dns:rr()], [erldns:keyset()]) -> erldns:zone().
build_zone(Name, Version, Records, Keys) ->
    NormalizedName = dns_domain:to_lower(Name),
    Labels = dns_domain:split(NormalizedName),
    Authorities = lists:filter(fun erldns_records:is_soa/1, Records),
    #zone{
        labels = Labels,
        reversed_labels = lists:reverse(Labels),
        name = NormalizedName,
        version = Version,
        record_count = length(Records),
        authority = Authorities,
        records = Records,
        keysets = Keys
    }.

-doc #{equiv => encode(Zone, #{mode => zone_to_json})}.
-spec encode(erldns:zone()) -> json:encode_value().
encode(Zone) ->
    encode(Zone, #{mode => zone_to_json}).

-doc """
Takes a zone and turns it into a map.

The records of the types erldns doesn't know are encoded by the `c:erldns_zone_pipeline:encode/1`
of the pipes of the zone pipeline.
""".
-spec encode(erldns:zone(), #{atom() => dynamic()}) -> json:encode_value().
encode(Zone, Opts) ->
    Encoders = erldns_zone_pipeline:encoders(),
    erldns_zone_encoder:encode(Zone, Opts, Encoders).

-doc "Takes a JSON map and turns it into a zone, as `decode/2` does with no options.".
-spec decode(json:decode_value()) -> erldns:zone().
decode(Zone) ->
    {Decoded, _} = decode(Zone, #{}),
    Decoded.

-doc """
Takes a JSON map and turns it into a zone, through `m:erldns_zone_pipeline`.

The pipes get `Opts` with the zone's name and version, and `scope` set to `zone` unless `Opts` sets
it. Returns the zone, and the options as the pipes left them.
""".
-spec decode(json:decode_value(), #{atom() => dynamic()}) ->
    {erldns:zone(), erldns_zone_pipeline:opts()}.
decode(#{~"name" := Name, ~"records" := JsonRecords} = Zone, Opts) ->
    Sha = maps:get(~"sha", Zone, ~""),
    JsonKeys = maps:get(~"keys", Zone, []),
    Keys = erldns_zone_decoder:parse_keysets(JsonKeys),
    Scoped = maps:merge(#{scope => zone}, Opts),
    RecordsOpts = Scoped#{zone_name => Name, version => Sha},
    {Records, Opts1} = decode_records(JsonRecords, RecordsOpts),
    Decoded = build_zone(Name, Sha, Records, Keys),
    {Decoded, Opts1}.

-doc """
Takes records of a zone, such as those of an RRSet, through `m:erldns_zone_pipeline`.

The records can be JSON or already decoded. The pipes get `Opts`, with `scope` set to `partial`
and `version` to `<<>>` unless `Opts` sets them. Returns the records, sorted and deduplicated, and
the options as the pipes left them.
""".
-spec decode_records(Entries, Opts) -> {[dns:rr()], erldns_zone_pipeline:opts()} when
    Entries :: [erldns_zone_pipeline:entry()],
    Opts :: #{zone_name := dns:dname(), atom() => dynamic()}.
decode_records(Entries, #{zone_name := _} = Opts) ->
    CallOpts = maps:merge(#{scope => partial, version => ~""}, Opts),
    {Decoded, Opts1} = erldns_zone_pipeline:run(Entries, CallOpts),
    Records = erldns_zone_decoder:finalize(Decoded),
    {Records, Opts1}.

% Internal API
-doc false.
-spec start_link() -> gen_server:start_ret().
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, noargs, [{hibernate_after, 0}]).

-doc false.
-spec init(noargs) -> {ok, state()}.
init(noargs) ->
    process_flag(trap_exit, true),
    Pipes = erldns_zone_pipeline:configured(),
    ok = erldns_zone_pipeline:store(Pipes),
    {ok, nostate}.

-doc false.
-spec handle_call(dynamic(), gen_server:from(), state()) ->
    {reply, dynamic(), state()}.
handle_call(Call, From, State) ->
    ?LOG_INFO(#{what => unexpected_call, from => From, call => Call}, #{domain => [erldns, zones]}),
    {reply, not_implemented, State}.

-doc false.
-spec handle_cast(dynamic(), state()) -> {noreply, state()}.
handle_cast(Cast, State) ->
    ?LOG_INFO(#{what => unexpected_cast, cast => Cast}, #{domain => [erldns, zones]}),
    {noreply, State}.

-doc false.
-spec terminate(term(), state()) -> term().
terminate(_, _) ->
    erldns_zone_pipeline:delete().
