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
        keys_path => "/root/dnssec/",
        strict => true,
        format => auto,
        timeout => timer:minutes(5),
        codecs => [sample_custom_zone_codec],
        context_options => #{match_empty => true, allow => [<<"anycast">>, <<"AMS">>, <<"TKO">>]}
    }},
]}
```

See the type `t:config/0` for details.
""".

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
  Both formats support custom codecs for handling unknown record types.
  Valid values are:
  - `json`: zones are parsed using `erldns`'s [`JSON`](priv/zones/ZONES.md#json-format) zone format.
  - `zonefile`: zones are parsed using the [`zone`](priv/zones/ZONES.md#zonefile-format) format.
  - `auto`:  both filetypes will be loaded depending on their file extension.

- `timeout`: specify how long zone loading can take before being aborted. Defaults to 30 minutes.

- `codecs`: a list of modules that implement the `m:erldns_zone_codec` behaviour.

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
    codecs => [module()],
    context_options => #{
        match_empty => boolean(),
        allow => [binary()]
    }
}.
-type version() :: binary().
-type format() :: json | zonefile | auto.
-export_type([config/0, version/0, format/0]).

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
            supervisor(erldns_zone_loader_sup)
        ],
    {ok, {SupFlags, Children}}.

-spec worker(module()) -> supervisor:child_spec().
worker(Module) ->
    #{id => Module, start => {Module, start_link, []}, type => worker}.

-spec supervisor(module()) -> supervisor:child_spec().
supervisor(Module) ->
    #{id => Module, start => {Module, start_link, []}, type => supervisor}.
