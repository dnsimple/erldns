-module(erldns_zones).
-moduledoc """
The system responsible for loading and caching zone data.

Zones are loaded by default from JSON files in the `priv/zones/` directory.
The path is configured in `erldns.config` using the `zones.path` setting.

Zones in JSON are decoded with `decode/2`, and encoded back with `encode/2`. Their records go
through `m:erldns_zone_pipeline`, whose pipes also decode the records of the types erldns doesn't
know, and encode them back.

For more details about zone file format and configuration, see [`ZONES`](priv/zones/ZONES.md).

For more details about its subsections, see:
- `m:erldns_zone_cache`
- `m:erldns_zone_pipeline`
- `m:erldns_zone_loader`

## Configuration

```erlang
{erldns, [
    {zones, #{
        path => "zones.json",
        keys_path => "/root/dnssec/",
        strict => true,
        format => auto,
        timeout => timer:minutes(5),
        grace_period => timer:seconds(30),
        pipeline => [erldns_zone_context, erldns_zone_standard, sample_custom_zone_pipe],
        context_options => #{match_empty => true, allow => [<<"anycast">>, <<"AMS">>, <<"TKO">>]}
    }},
]}
```

See the type `t:config/0` for details.
""".

-include_lib("dns_erlang/include/dns.hrl").
-include_lib("kernel/include/logger.hrl").
-include_lib("erldns/include/erldns.hrl").

-define(LOG_METADATA, #{domain => [erldns, zones, decoder]}).

-doc """
Zone configuration.

- `path`: can be a file or a directory:
  - If it is a file, `format` will be ignored
  - If it is a directory, it will find all nested files matching the format specified in `format`

- `strict`: declares whether any loading error should crash the whole loading process or be ignored.

- `keys_path`: specifies the path to DNSSEC keys used for signing and validating zones.
  These file should be named after the zone name with the `.private` file extension
  (i.e.: "example.com.private") and should contain a JSON formatted list of keysets as in the
  [`JSON`](priv/zones/ZONES.md#json-format) zone format documentation.

- `format`: specifies the zone file format to look for.
  The records of both formats go through the zone pipeline, those of zone files already decoded.
  Valid values are:
  - `json`: zones are parsed using `erldns`'s [`JSON`](priv/zones/ZONES.md#json-format) zone format.
  - `zonefile`: zones are parsed using the [`zone`](priv/zones/ZONES.md#zonefile-format) format.
  - `auto`:  both filetypes will be loaded depending on their file extension.

- `timeout`: specify how long zone loading can take before being aborted. Defaults to 30 minutes.

- `grace_period`: how long, in milliseconds, the records of a replaced or deleted zone stay
  readable for queries that started on them, before they are deleted. Defaults to 30 seconds.

- `pipeline`: the pipes that the records of a zone go through when it is decoded, see
  `m:erldns_zone_pipeline`. Defaults to `m:erldns_zone_context` and `m:erldns_zone_standard`, and
  the pipes that decode custom record types go after them. Not to be confused with the top-level
  `pipeline` and `packet_pipeline` keys, which are about queries.

- `context_options`: allow you to filter loading certain records in a zone
  depending on configuration details. See [`ZONES`](priv/zones/ZONES.md) for more details.

See `m:erldns_zone_loader` for more details.
""".
-type config() :: #{
    path => undefined | file:name_all(),
    keys_path => undefined | file:name_all(),
    strict => boolean(),
    format => format(),
    timeout => timeout(),
    grace_period => non_neg_integer(),
    pipeline => [erldns_zone_pipeline:pipe()],
    context_options => #{
        match_empty => boolean(),
        allow => [binary()]
    }
}.
-type version() :: binary().
-type format() :: json | zonefile | auto.
-export_type([config/0, version/0, format/0]).

-behaviour(supervisor).

-export([build_zone/4, encode/1, encode/2, decode/1, decode/2, decode_records/2]).

-export([start_link/0, init/1]).

-doc "Builds a zone from its records and keysets.".
-spec build_zone(dns:dname(), version(), [dns:rr()], [erldns:keyset()]) -> erldns:zone().
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
    decode(Zone, #{}).

-doc """
Takes a JSON map and turns it into a zone, through `m:erldns_zone_pipeline`.

The pipes get `Opts` with the zone's name and version, and `scope` set to `zone` unless `Opts` sets
it.
""".
-spec decode(json:decode_value(), #{atom() => dynamic()}) -> erldns:zone().
decode(#{~"name" := Name, ~"records" := JsonRecords} = Zone, Opts) ->
    Sha = maps:get(~"sha", Zone, ~""),
    JsonKeys = maps:get(~"keys", Zone, []),
    Keys = erldns_zone_decoder:parse_keysets(JsonKeys),
    Scope = maps:get(scope, Opts, zone),
    CallOpts = Opts#{zone_name => Name, version => Sha, scope => Scope},
    Records = run_pipeline(JsonRecords, CallOpts),
    build_zone(Name, Sha, Records, Keys).

-doc """
Takes records of a zone, such as those of an RRSet, through `m:erldns_zone_pipeline`.

The records can be JSON or already decoded. The pipes get `Opts`, with `scope` set to `partial`
and `version` to `<<>>` unless `Opts` sets them. Returns the records, sorted and deduplicated.
""".
-spec decode_records(Entries, Opts) -> [dns:rr()] when
    Entries :: [erldns_zone_pipeline:entry()],
    Opts :: #{zone_name := dns:dname(), atom() => dynamic()}.
decode_records(Entries, #{zone_name := _} = Opts) ->
    CallOpts = maps:merge(#{scope => partial, version => ~""}, Opts),
    run_pipeline(Entries, CallOpts).

-doc false.
-spec start_link() -> supervisor:startlink_ret().
start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, noargs).

-doc false.
-spec init(noargs) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init(noargs) ->
    SupFlags = #{strategy => rest_for_one, intensity => 1, period => 5},
    Children =
        [
            worker(erldns_zone_cache),
            worker(erldns_zone_pipeline_worker),
            supervisor(erldns_zone_loader_sup)
        ],
    {ok, {SupFlags, Children}}.

run_pipeline(Entries, CallOpts) ->
    Decoded = erldns_zone_pipeline:run(Entries, CallOpts),
    finalize(Decoded).

-spec finalize([erldns_zone_pipeline:entry()]) -> [dns:rr()].
finalize(Entries) ->
    Records = lists:filter(fun is_decoded/1, Entries),
    lists:usort(Records).

is_decoded(#dns_rr{}) ->
    true;
is_decoded(Entry) ->
    ?LOG_WARNING(#{what => unsupported_record, record => Entry}, ?LOG_METADATA),
    false.

-spec worker(module()) -> supervisor:child_spec().
worker(Module) ->
    #{id => Module, start => {Module, start_link, []}, type => worker}.

-spec supervisor(module()) -> supervisor:child_spec().
supervisor(Module) ->
    #{id => Module, start => {Module, start_link, []}, type => supervisor}.
