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
        codecs => [sample_custom_zone_codec]
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

Codecs are a list of modules that implement the `m:erldns_zone_codec` behaviour.
""".
-type config() :: #{
    path => undefined | file:name(),
    strict => boolean(),
    codecs => [module()]
}.
-type version() :: binary().
-export_type([config/0, version/0]).

-behaviour(supervisor).

-export([start_link/0, init/1]).

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
            worker(erldns_zone_loader)
        ],
    {ok, {SupFlags, Children}}.

worker(Module) ->
    #{id => Module, start => {Module, start_link, []}, type => worker}.
