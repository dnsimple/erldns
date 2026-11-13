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
needs the records of standard types as JSON goes before `m:erldns_zone_standard`, and
`m:erldns_zone_context` goes first for records to be filtered by context:

```erlang
{erldns, [
    {zones, #{
        pipeline => [
            erldns_zone_context,
            sample_rewrite_pipe,
            erldns_zone_standard,
            sample_custom_zone_codec
        ]
    }}
]}
```

Without `pipeline`, the pipes are `m:erldns_zone_context` and `m:erldns_zone_standard`. Codecs
registered with `erldns_zone_codec:register_codecs/1` are added at the end.

## Types of pipes

- A module that implements this behaviour: `c:call/2`, and optionally `c:prepare/1` and
  `c:deps/0`, which work as in `m:erldns_pipeline`.
- A function of arity 2, called as `c:call/2`.
- A module that implements `m:erldns_zone_codec`: its `c:erldns_zone_codec:decode/1` is applied
  to each JSON record, and a record is left as it is when it returns `not_implemented`. Codecs next
  to each other share one pass over the records, and the first that decodes a record wins.

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

-include_lib("dns_erlang/include/dns.hrl").
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

-type step() :: {pipe, pipe(), pipefun()} | {codecs, [erldns_zone_codec:decoder()]}.

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

-optional_callbacks([prepare/1, deps/0]).

-export([configured/0, validate_codecs/1, store/1, delete/0, run/2]).
-export([prepare/1, run/3]).

-doc false.
-spec configured() -> [pipe()].
configured() ->
    ZonesConfig = application:get_env(erldns, zones, #{}),
    configured(ZonesConfig).

-doc false.
-spec validate_codecs([module()]) -> ok.
validate_codecs(Modules) ->
    lists:foreach(fun validate_codec/1, Modules).

-doc false.
-spec store([pipe()]) -> ok.
store(Pipes) ->
    Prepared = prepare(Pipes),
    persistent_term:put(?MODULE, Prepared).

-doc false.
-spec delete() -> boolean().
delete() ->
    persistent_term:erase(?MODULE).

%% Without a stored pipeline, as when the zone codec server isn't running, the configured one is
%% prepared for each call: running fewer pipes could load records that a pipe would have changed
-doc false.
-spec run([entry()], #{atom() => dynamic()}) -> {[entry()], opts()}.
run(Entries, CallOpts) ->
    case persistent_term:get(?MODULE, undefined) of
        undefined ->
            Pipes = configured(),
            Prepared = prepare(Pipes),
            run(Entries, CallOpts, Prepared);
        Prepared ->
            run(Entries, CallOpts, Prepared)
    end.

-doc false.
-spec prepare([pipe()]) -> prepared().
prepare(Pipes) ->
    Init = {[], [], def_opts()},
    Prepare = fun(Pipe, Acc) -> prepare_pipe(Pipe, Acc, Pipes) end,
    {Steps, Decoders, Opts} = lists:foldl(Prepare, Init, Pipes),
    Flushed = flush(Decoders, Steps),
    Pipeline = lists:reverse(Flushed),
    {Pipeline, Opts}.

-doc false.
-spec run([entry()], #{atom() => dynamic()}, prepared()) -> {[entry()], opts()}.
run(Entries, CallOpts, {Pipeline, PreparedOpts}) ->
    Opts = maps:merge(PreparedOpts, CallOpts),
    lists:foldl(fun run_step/2, {Entries, Opts}, Pipeline).

%% The removed codecs key fails, so its codecs aren't left out of the pipeline unnoticed
configured(#{codecs := _}) ->
    erlang:error({badconfig, codecs_moved_to_pipeline});
configured(#{pipeline := Pipes}) when is_list(Pipes) ->
    Pipes;
configured(#{pipeline := Pipes}) ->
    erlang:error({badconfig, {invalid_pipeline, Pipes}});
configured(_) ->
    ?DEFAULT_PIPES.

validate_codec(Module) ->
    maybe
        {module, Module} ?= code:ensure_loaded(Module),
        true ?= erlang:function_exported(Module, encode, 1),
        true ?= erlang:function_exported(Module, decode, 1)
    else
        {error, Reason} -> erlang:error({badcodec, {module, Reason}});
        false -> erlang:error({badcodec, {module_does_not_export_call, Module}})
    end.

prepare_pipe(Fun, {Steps, Decoders, Opts}, _) when is_function(Fun, 2) ->
    Flushed = flush(Decoders, Steps),
    {[{pipe, Fun, Fun} | Flushed], [], Opts};
prepare_pipe(Fun, _, _) when is_function(Fun) ->
    erlang:error({badpipe, {function_pipe_has_wrong_arity, Fun}});
prepare_pipe(Module, Acc, Pipes) when is_atom(Module) ->
    ok = ensure_loaded(Module),
    prepare_module(Module, Acc, Pipes).

prepare_module(Module, {Steps, Decoders, Opts} = Acc, Pipes) ->
    IsPipe = erlang:function_exported(Module, call, 2),
    IsCodec = erlang:function_exported(Module, decode, 1),
    case {IsPipe, IsCodec} of
        {true, _} -> prepare_call(Module, Acc, Pipes);
        {false, true} -> {Steps, [fun Module:decode/1 | Decoders], Opts};
        {false, false} -> erlang:error({badpipe, {module_does_not_export_call, Module}})
    end.

%% A disabled pipe leaves the codecs around it in one step
prepare_call(Module, {Steps, Decoders, Opts}, Pipes) ->
    ok = ensure_dependencies(Module, Pipes),
    case maybe_prepare(Module, Opts) of
        disabled ->
            ?LOG_DEBUG(#{what => zone_pipe_disabled, module => Module}, ?LOG_METADATA),
            {Steps, Decoders, Opts};
        Opts1 ->
            Flushed = flush(Decoders, Steps),
            {[{pipe, Module, fun Module:call/2} | Flushed], [], Opts1}
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

flush([], Steps) ->
    Steps;
flush(Decoders, Steps) ->
    Ordered = lists:reverse(Decoders),
    [{codecs, Ordered} | Steps].

run_step({codecs, Decoders}, {Entries, Opts}) ->
    Decoded = decode_all(Entries, Decoders),
    {Decoded, Opts};
run_step({pipe, Pipe, Fun}, {Entries, Opts}) ->
    case Fun(Entries, Opts) of
        Next when is_list(Next) -> {Next, Opts};
        {Next, NextOpts} when is_list(Next), is_map(NextOpts) -> {Next, NextOpts};
        {error, Reason} -> erlang:error({zone_rejected, Pipe, Reason});
        Other -> erlang:error({bad_zone_pipe_return, Pipe, Other})
    end.

decode_all(Entries, Decoders) ->
    [decode_entry(Entry, Decoders) || Entry <- Entries].

decode_entry(#{} = JsonRecord, Decoders) ->
    try_decoders(JsonRecord, Decoders);
decode_entry(Entry, _) ->
    Entry.

try_decoders(JsonRecord, []) ->
    JsonRecord;
try_decoders(JsonRecord, [Decoder | Rest]) ->
    case Decoder(JsonRecord) of
        not_implemented -> try_decoders(JsonRecord, Rest);
        #dns_rr{} = Record -> Record
    end.

def_opts() ->
    #{zone_name => ~"", version => ~"", scope => zone}.
