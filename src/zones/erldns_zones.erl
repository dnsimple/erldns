-module(erldns_zones).
-moduledoc """
The system responsible for loading and caching zone data.

Zones are loaded by default from JSON files in the `priv/zones/` directory.
The path is configured in `erldns.config` using the `zones.path` setting.

For more details about zone file format and configuration, see [`ZONES`](priv/zones/ZONES.md).

For more details about its subsections, see:
- `m:erldns_zone_cache`
- `m:erldns_zone_codec`
- `m:erldns_zone_loader`

## Configuration
```erlang
{erldns, [
    {zones, #{
        path => "zones.json",
        strict => true,
        format => json,  % or zonefile, or auto (default: json)
        timeout => timer:minutes(30),
        codecs => [sample_custom_zone_codec],
        context_options => #{match_empty => true, allow => [<<"anycast">>, <<"AMS">>, <<"TKO">>],
        rfc_compliant_ent => true}
    }},
]}
```

See the type `t:config/0` for details.
""".

-doc """
Zone configuration.

Path can be a directory, and `strict` declares whether load failure should crash or be ignored.
If a path is configured and `strict` is true, and the path is not resolvable, it will fail.
See `m:erldns_zone_loader` for more details.

Format specifies the zone file format: `json` (default) or `zonefile`. When `zonefile` is used,
zones are parsed using dns_erlang's zonefile parser. Both formats support custom codecs for
handling unknown record types.

Timeouts specify how long zone loading can take before being aborted. Defaults to 30 minutes.

Codecs are a list of modules that implement the `m:erldns_zone_codec` behaviour.

Context options allow you to filter loading certain records in a zone depending on configuration
details. See [`ZONES`](priv/zones/ZONES.md) for more details.

`rfc_compliant_ent` updates the handling of empty non-terminals ENTs to be complaint with RFC 4592.
When set to `true`, ENTs will be used as the source of wildcard synthesis if applicable. Defaults to
`false` in order to keep the old behaviour.
""".
-type config() :: #{
    path => undefined | file:name(),
    strict => boolean(),
    format => format(),
    timeout => timeout(),
    codecs => [module()],
    context_options => #{
        match_empty => boolean(),
        allow => [binary()]
    },
    rfc_compliant_ent => boolean()
}.
-type version() :: binary().
-type format() :: json | zonefile | auto.
-export_type([config/0, version/0, format/0]).

-behaviour(supervisor).

-export([start_link/0, init/1, rfc_compliant_ent_enabled/0]).

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
            worker(erldns_zone_codec),
            supervisor(erldns_zone_loader_sup)
        ],
    {ok, {SupFlags, Children}}.

-doc false.
-spec rfc_compliant_ent_enabled() -> boolean().
rfc_compliant_ent_enabled() ->
    case application:get_env(erldns, zones, #{}) of
        #{rfc_compliant_ent := Val} when is_boolean(Val) -> Val;
        #{} -> false
    end.

-spec worker(module()) -> supervisor:child_spec().
worker(Module) ->
    #{id => Module, start => {Module, start_link, []}, type => worker}.

-spec supervisor(module()) -> supervisor:child_spec().
supervisor(Module) ->
    #{id => Module, start => {Module, start_link, []}, type => supervisor}.
