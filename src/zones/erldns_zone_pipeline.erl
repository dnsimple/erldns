-module(erldns_zone_pipeline).
-moduledoc """
A pipeline of pipes that the records of a zone go through when the zone is decoded.

Each pipe takes the records and returns them, changed or not, to the next pipe. A record is an
`t:entry/0`: a JSON record not yet decoded, or a `t:dns:rr/0`. Decoding is itself a pipe:
`m:erldns_zone_standard` turns the JSON records of the types it knows into `t:dns:rr/0` and leaves
the rest, so a pipe placed before it sees every record as JSON, with the keys erldns doesn't use.
After the last pipe, the JSON records left are logged as unsupported and dropped, and the records
are sorted and deduplicated.

## Configuration

The `pipeline` key of the `zones` configuration lists the pipes, see `m:erldns_zones`. A pipe that
needs the records of standard types as JSON goes before `m:erldns_zone_standard`, a pipe that
decodes a custom record type goes after it, and `m:erldns_zone_context` goes first for records to
be filtered by context:

```erlang
{erldns, [
    {zones, #{
        pipeline => [
            erldns_zone_context,
            sample_rewrite_pipe,
            erldns_zone_standard,
            sample_custom_zone_pipe
        ]
    }}
]}
```

Without `pipeline`, the pipes are `m:erldns_zone_context` and `m:erldns_zone_standard`.

## Types of pipes

- A module that implements this behaviour: `c:call/2`, and optionally `c:prepare/1` and
  `c:deps/0`, which work as in `m:erldns_pipeline`, and `c:encode/1`, see
  [Custom record types](#module-custom-record-types).
- A function of arity 2, called as `c:call/2`.

## Custom record types

A pipe placed after `m:erldns_zone_standard` gets the JSON records of the types erldns doesn't
know, and can decode them into `t:dns:rr/0`. To encode them back to JSON, as
`erldns_zone_codec:encode/1,2` and the admin API do, it implements `c:encode/1`. The pipes of the
pipeline are tried in order, the first that doesn't return `not_implemented` encodes the record,
and a record that none encodes is left out.

```erlang
-module(sample_custom_zone_pipe).
-behaviour(erldns_zone_pipeline).

-include_lib("dns_erlang/include/dns.hrl").

-export([call/2, encode/1]).

-define(DNS_TYPE_SAMPLE, 40000).

call(Entries, _Opts) ->
    [decode(Entry) || Entry <- Entries].

decode(#{~"name" := Name, ~"type" := ~"SAMPLE", ~"ttl" := Ttl, ~"data" := Data}) ->
    #dns_rr{name = Name, type = ?DNS_TYPE_SAMPLE, data = maps:get(~"dname", Data), ttl = Ttl};
decode(Entry) ->
    Entry.

encode(#dns_rr{name = Name, type = ?DNS_TYPE_SAMPLE, ttl = Ttl, data = Data}) ->
    #{
        ~"name" => erlang:iolist_to_binary(io_lib:format("~s.", [Name])),
        ~"type" => ~"SAMPLE",
        ~"ttl" => Ttl,
        ~"content" => Data
    };
encode(_) ->
    not_implemented.
```

## Scope

The `scope` option says whether a pipe sees a whole zone, `zone`, or a part of one, `partial`, such
as an RRSet. A pipe passes on the records it doesn't handle, and doesn't assume it sees all the
records of a zone under `partial`.

## Failures

The pipeline doesn't catch exceptions. A pipe that raises, or that returns `{error, Reason}`, fails
the decode of the zone, so that a zone is never loaded with a pipe skipped. In this it differs from
`m:erldns_pipeline`.

## Example

A pipe that caps the TTL of the records, once they are decoded:

```erlang
-module(example_ttl_cap).
-behaviour(erldns_zone_pipeline).

-include_lib("dns_erlang/include/dns.hrl").

-export([deps/0, call/2]).

deps() ->
    #{prerequisites => [erldns_zone_standard]}.

call(Entries, _Opts) ->
    [cap(Entry) || Entry <- Entries].

cap(#dns_rr{ttl = Ttl} = Record) when Ttl > 86400 ->
    Record#dns_rr{ttl = 86400};
cap(Entry) ->
    Entry.
```
""".

-include_lib("kernel/include/logger.hrl").

-define(LOG_METADATA, #{domain => [erldns, zones, pipeline]}).
-define(DEFAULT_PIPES, [erldns_zone_context, erldns_zone_standard]).

-doc "A record as it was in the JSON zone.".
-type json_record() :: #{binary() => json:decode_value()}.

-doc "A record going through the pipeline, decoded or not.".
-type entry() :: dns:rr() | json_record().

-doc "Whether the records are a whole zone, or a part of one.".
-type scope() :: zone | partial.

-doc """
Options passed to every pipe.

The zone's name and version are as the zone was given. Pipes can add their own keys.
""".
-type opts() :: #{
    zone_name := dns:dname(),
    version := erldns_zones:version(),
    scope := scope(),
    atom() => dynamic()
}.

-doc """
The return of a pipe.

- The records, for the next pipe.
- The records and new options, for the next pipes.
- `{error, Reason}`, to fail the decode of the zone.
""".
-type return() :: [entry()] | {[entry()], opts()} | {error, term()}.

-doc "A function pipe.".
-type pipefun() :: fun(([entry()], opts()) -> return()).

-doc "A pipe in the pipeline, see [Types of pipes](#module-types-of-pipes).".
-type pipe() :: module() | pipefun().

-type step() :: {pipe(), pipefun()}.

-doc "A pipeline ready to run.".
-opaque prepared() :: {[step()], opts()}.

-export_type([json_record/0, entry/0, scope/0, opts/0, return/0, pipefun/0, pipe/0]).
-export_type([prepared/0]).

-doc "Take the records and return them, changed or not. See `t:return/0`.".
-callback call([entry()], opts()) -> return().

-doc """
Prepare the pipe when the pipeline is prepared, adding to the options what it needs, or return
`disabled` to leave the pipe out.

It can be called more than once, and isn't called again for each zone.
""".
-callback prepare(opts()) -> disabled | opts().

-doc "Declare the pipes this one needs before or after it. See `t:erldns_pipeline:deps/0`.".
-callback deps() -> erldns_pipeline:deps().

-doc """
Encode a record that this pipe decoded back to JSON, or return `not_implemented`. See
[Custom record types](#module-custom-record-types).
""".
-callback encode(dns:rr()) -> not_implemented | json:encode_value().

-optional_callbacks([prepare/1, deps/0, encode/1]).

-export([configured/0, store/1, delete/0, run/2, encoders/0]).
-export([prepare/1, run/3]).

-doc false.
-spec configured() -> [pipe()].
configured() ->
    ZonesConfig = application:get_env(erldns, zones, #{}),
    configured(ZonesConfig).

-doc false.
-spec store([pipe()]) -> ok.
store(Pipes) ->
    Prepared = prepare(Pipes),
    Encoders = encoders(Pipes),
    persistent_term:put(?MODULE, {Prepared, Encoders}).

-doc false.
-spec delete() -> boolean().
delete() ->
    persistent_term:erase(?MODULE).

-doc false.
-spec run([entry()], #{atom() => dynamic()}) -> {[entry()], opts()}.
run(Entries, CallOpts) ->
    {Prepared, _} = stored(),
    run(Entries, CallOpts, Prepared).

%% The encode/1 of the pipes, in the order of the pipeline
-doc false.
-spec encoders() -> [erldns_zone_encoder:encoder()].
encoders() ->
    {_, Encoders} = stored(),
    Encoders.

-doc false.
-spec prepare([pipe()]) -> prepared().
prepare(Pipes) ->
    Prepare = fun(Pipe, Acc) -> prepare_pipe(Pipe, Acc, Pipes) end,
    {Steps, Opts} = lists:foldl(Prepare, {[], def_opts()}, Pipes),
    Pipeline = lists:reverse(Steps),
    {Pipeline, Opts}.

-doc false.
-spec run([entry()], #{atom() => dynamic()}, prepared()) -> {[entry()], opts()}.
run(Entries, CallOpts, {Pipeline, PreparedOpts}) ->
    Opts = maps:merge(PreparedOpts, CallOpts),
    lists:foldl(fun run_step/2, {Entries, Opts}, Pipeline).

%% Without a stored pipeline, as when the zone codec server isn't running, the configured one is
%% prepared for each call: running fewer pipes could load records that a pipe would have changed
stored() ->
    case persistent_term:get(?MODULE, undefined) of
        undefined ->
            Pipes = configured(),
            Prepared = prepare(Pipes),
            Encoders = encoders(Pipes),
            {Prepared, Encoders};
        Stored ->
            Stored
    end.

%% The removed codecs key fails, so its codecs aren't left out of the pipeline unnoticed
configured(#{codecs := _}) ->
    erlang:error({badconfig, codecs_moved_to_pipeline});
configured(#{pipeline := Pipes}) when is_list(Pipes) ->
    Pipes;
configured(#{pipeline := Pipes}) ->
    erlang:error({badconfig, {invalid_pipeline, Pipes}});
configured(_) ->
    ?DEFAULT_PIPES.

%% prepare/1 has loaded the modules
encoders(Pipes) ->
    Modules = [Pipe || Pipe <- Pipes, is_atom(Pipe)],
    [fun Module:encode/1 || Module <- Modules, erlang:function_exported(Module, encode, 1)].

prepare_pipe(Fun, {Steps, Opts}, _) when is_function(Fun, 2) ->
    {[{Fun, Fun} | Steps], Opts};
prepare_pipe(Fun, _, _) when is_function(Fun) ->
    erlang:error({badpipe, {function_pipe_has_wrong_arity, Fun}});
prepare_pipe(Module, Acc, Pipes) when is_atom(Module) ->
    ok = ensure_loaded(Module),
    case erlang:function_exported(Module, call, 2) of
        true -> prepare_module(Module, Acc, Pipes);
        false -> erlang:error({badpipe, {module_does_not_export_call, Module}})
    end.

prepare_module(Module, {Steps, Opts} = Acc, Pipes) ->
    ok = ensure_dependencies(Module, Pipes),
    case maybe_prepare(Module, Opts) of
        disabled ->
            ?LOG_DEBUG(#{what => zone_pipe_disabled, module => Module}, ?LOG_METADATA),
            Acc;
        Opts1 ->
            {[{Module, fun Module:call/2} | Steps], Opts1}
    end.

ensure_loaded(Module) ->
    case code:ensure_loaded(Module) of
        {module, Module} -> ok;
        {error, Reason} -> erlang:error({badpipe, {module, Reason}})
    end.

ensure_dependencies(Module, Pipes) ->
    maybe
        true ?= erlang:function_exported(Module, deps, 0),
        Deps = Module:deps(),
        {error, Reason} ?= erldns_pipe_deps:check(Module, Deps, Pipes),
        erlang:error({badpipe, Reason})
    else
        false -> ok;
        ok -> ok
    end.

maybe_prepare(Module, Opts) ->
    case erlang:function_exported(Module, prepare, 1) andalso Module:prepare(Opts) of
        false -> Opts;
        disabled -> disabled;
        Opts1 when is_map(Opts1) -> Opts1;
        _ -> erlang:error({badpipe, {module_init_returned_non_map, Module}})
    end.

run_step({Pipe, Fun}, {Entries, Opts}) ->
    case Fun(Entries, Opts) of
        Next when is_list(Next) -> {Next, Opts};
        {Next, NextOpts} when is_list(Next), is_map(NextOpts) -> {Next, NextOpts};
        {error, Reason} -> erlang:error({zone_rejected, Pipe, Reason});
        Other -> erlang:error({bad_zone_pipe_return, Pipe, Other})
    end.

def_opts() ->
    #{zone_name => ~"", version => ~"", scope => zone}.
