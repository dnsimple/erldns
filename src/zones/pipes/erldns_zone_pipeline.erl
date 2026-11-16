-module(erldns_zone_pipeline).
-moduledoc """
A pipeline of pipes that the records of a zone go through when the zone is decoded.

A record is an `t:entry/0`: a JSON record not yet decoded, a `t:dns:rr/0`, or a pipe's own
`{Module, Term}`. A pipe implements either or both of two callbacks:

- `c:decode_record/3` takes one record: the record as the pipeline was given it, and the record as
  the pipes before it left it. It returns the record, changed or not, or drops it.
- `c:decode/2` takes all the records at once, to relate them to each other, and returns them,
  changed or not.

The `c:decode_record/3` of every pipe runs first, in the order of the pipeline, all in a single pass
over the records. Then the `c:decode/2` of every pipe runs, in the same order. After the last pipe,
the records that aren't a `t:dns:rr/0` are logged as unsupported and dropped, and the records are
sorted and deduplicated.

Decoding is itself a pipe: `m:erldns_zone_standard` turns the JSON records of the types it knows
into `t:dns:rr/0` and leaves the rest. The pipes after it still get each record as it was given, in
JSON, with the keys erldns doesn't use, as the first argument of `c:decode_record/3`.

## Configuration

The `pipeline` key of the `zones` configuration lists the pipes, see `m:erldns_zones`.
`m:erldns_zone_context` goes first, so that the records it drops aren't decoded, and a pipe that
decodes a custom record type goes after `m:erldns_zone_standard`:

```erlang
{erldns, [
    {zones, #{
        pipeline => [
            erldns_zone_context,
            erldns_zone_standard,
            sample_custom_zone_pipe,
            example_ttl_cap
        ]
    }}
]}
```

Without `pipeline`, the pipes are `m:erldns_zone_context` and `m:erldns_zone_standard`.

## Types of pipes

- A module that implements this behaviour: `c:decode_record/3`, `c:decode/2` or both, and
  optionally `c:prepare/1` and `c:deps/0`, which work as in `m:erldns_pipeline`, and `c:encode/1`,
  see [Custom record types](#module-custom-record-types). The order that `c:deps/0` asks for holds
  among the `c:decode_record/3` callbacks, and among the `c:decode/2` callbacks.
- A function of arity 3, called as `c:decode_record/3`, or of arity 2, called as `c:decode/2`.

## Custom record types

A pipe placed after `m:erldns_zone_standard` gets the JSON records of the types erldns doesn't
know, and can decode them into `t:dns:rr/0`. To encode them back to JSON, as
`erldns_zones:encode/1,2` and the admin API do, it implements `c:encode/1`. The pipes of the
pipeline are tried in order, the first that doesn't return `not_implemented` encodes the record,
and a record that none encodes is left out.

```erlang
-module(sample_custom_zone_pipe).
-behaviour(erldns_zone_pipeline).

-include_lib("dns_erlang/include/dns.hrl").

-export([decode_record/3, encode/1]).

-define(DNS_TYPE_SAMPLE, 40000).

decode_record(_, #{~"type" := ~"SAMPLE"} = Json, _Opts) ->
    #{~"name" := Name, ~"ttl" := Ttl, ~"data" := #{~"dname" := Dname}} = Json,
    #dns_rr{name = Name, type = ?DNS_TYPE_SAMPLE, data = Dname, ttl = Ttl};
decode_record(_, Entry, _Opts) ->
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

## From one record to all of them

A pipe whose `c:decode/2` needs what only a record's JSON says returns `{Module, Term}` from its
`c:decode_record/3`, with its own module, and replaces those entries in its `c:decode/2`. Other
pipes pass them on as they are, and one left at the end is logged as unsupported and dropped.

## Scope

The `scope` option says whether a pipe sees a whole zone, `zone`, or a part of one, `partial`, such
as an RRSet. A pipe passes on the records it doesn't handle, and doesn't assume it sees all the
records of a zone under `partial`.

## Failures

The pipeline doesn't catch exceptions. A pipe that raises, or that returns `{error, Reason}` from
either callback, fails the decode of the zone, so that a zone is never loaded with a pipe skipped.
In this it differs from `m:erldns_pipeline`.

## Example

A pipe that caps the TTL of the records, once they are decoded:

```erlang
-module(example_ttl_cap).
-behaviour(erldns_zone_pipeline).

-include_lib("dns_erlang/include/dns.hrl").

-export([deps/0, decode_record/3]).

deps() ->
    #{prerequisites => [erldns_zone_standard]}.

decode_record(_, #dns_rr{ttl = Ttl} = Record, _Opts) when Ttl > 86400 ->
    Record#dns_rr{ttl = 86400};
decode_record(_, Entry, _Opts) ->
    Entry.
```
""".

-include_lib("kernel/include/logger.hrl").

-define(LOG_METADATA, #{domain => [erldns, zones, pipeline]}).
-define(DEFAULT_PIPES, [erldns_zone_context, erldns_zone_standard]).

-doc "A record as it was in the JSON zone.".
-type json_record() :: #{binary() => json:decode_value()}.

-doc "A record going through the pipeline: in JSON, decoded, or a pipe's own term.".
-type entry() :: dns:rr() | json_record() | {module(), term()}.

-doc "Whether the records are a whole zone, or a part of one.".
-type scope() :: zone | partial.

-doc """
Options passed to every pipe.

The zone's name and version are as the zone was given. Pipes add their own keys in `c:prepare/1`,
and `c:decode/2` can change them for the pipes after it.
""".
-type opts() :: #{
    zone_name := dns:dname(),
    version := erldns_zones:version(),
    scope := scope(),
    atom() => dynamic()
}.

-doc """
The return of `c:decode_record/3`.

- The record, changed or not, for the next pipe.
- `drop`, to leave the record out.
- `{error, Reason}`, to fail the decode of the zone.
""".
-type record_return() :: entry() | drop | {error, term()}.

-doc """
The return of `c:decode/2`.

- The records, for the next pipe.
- The records and new options, for the next pipes.
- `{error, Reason}`, to fail the decode of the zone.
""".
-type return() :: [entry()] | {[entry()], opts()} | {error, term()}.

-doc "A function pipe called as `c:decode_record/3`.".
-type recordfun() :: fun((entry(), entry(), opts()) -> record_return()).

-doc "A function pipe called as `c:decode/2`.".
-type pipefun() :: fun(([entry()], opts()) -> return()).

-doc "A pipe in the pipeline, see [Types of pipes](#module-types-of-pipes).".
-type pipe() :: module() | recordfun() | pipefun().

-doc "A pipeline ready to run: the functions of its pipes, and its options.".
-opaque prepared() ::
    {[recordfun()], [pipefun()], [erldns_zone_encoder:encoder()], opts()}.

-export_type([json_record/0, entry/0, scope/0, opts/0, record_return/0, return/0]).
-export_type([recordfun/0, pipefun/0, pipe/0, prepared/0]).

-doc """
Take a record and return it, changed or not, or `drop` it. See `t:record_return/0`.

`Source` is the record as the pipeline was given it, and `Entry` the record as the pipes before this
one left it.
""".
-callback decode_record(Source :: entry(), Entry :: entry(), opts()) -> record_return().

-doc "Take all the records, after every `c:decode_record/3`, and return them. See `t:return/0`.".
-callback decode([entry()], opts()) -> return().

-doc """
Prepare the pipe when the pipeline is prepared, or return `disabled` to leave the pipe out.

A pipe adds the keys it uses to the options here, so that every decode starts with them and its
`c:decode/2` can update them with `:=`.
""".
-callback prepare(opts()) -> disabled | opts().

-doc "Declare the pipes this one needs before or after it. See `t:erldns_pipeline:deps/0`.".
-callback deps() -> erldns_pipeline:deps().

-doc """
Encode a record that this pipe decoded back to JSON, or return `not_implemented`. See
[Custom record types](#module-custom-record-types).
""".
-callback encode(dns:rr()) -> not_implemented | json:encode_value().

-optional_callbacks([decode_record/3, decode/2, prepare/1, deps/0, encode/1]).

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
    persistent_term:put(?MODULE, Prepared).

-doc false.
-spec delete() -> boolean().
delete() ->
    persistent_term:erase(?MODULE).

-doc false.
-spec run([entry()], opts()) -> {[entry()], opts()}.
run(Entries, CallOpts) ->
    Prepared = stored(),
    run(Entries, CallOpts, Prepared).

%% The encode/1 of the pipes, in the order of the pipeline
-doc false.
-spec encoders() -> [erldns_zone_encoder:encoder()].
encoders() ->
    {_, _, Encoders, _} = stored(),
    Encoders.

-doc false.
-spec prepare([pipe()]) -> prepared().
prepare(Pipes) ->
    Prepare = fun(Pipe, Acc) -> prepare_pipe(Pipe, Acc, Pipes) end,
    Init = {[], [], [], def_opts()},
    {RecordDecoders, Decoders, Encoders, Opts} = lists:foldl(Prepare, Init, Pipes),
    {lists:reverse(RecordDecoders), lists:reverse(Decoders), lists:reverse(Encoders), Opts}.

-doc false.
-spec run([entry()], opts(), prepared()) -> {[entry()], opts()}.
run(Entries, #{zone_name := _, version := _, scope := _} = CallOpts, Prepared) ->
    {RecordDecoders, Decoders, _, PreparedOpts} = Prepared,
    Opts = maps:merge(PreparedOpts, CallOpts),
    Records = run_records(Entries, RecordDecoders, Opts),
    lists:foldl(fun run_step/2, {Records, Opts}, Decoders).

%% Without a stored pipeline, as when its worker isn't running, the configured one is
%% prepared for each call: running fewer pipes could load records that a pipe would have changed
stored() ->
    case persistent_term:get(?MODULE, undefined) of
        undefined ->
            Pipes = configured(),
            prepare(Pipes);
        Prepared ->
            Prepared
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

prepare_pipe(Fun, {RecordDecoders, Decoders, Encoders, Opts}, _) when is_function(Fun, 3) ->
    {[Fun | RecordDecoders], Decoders, Encoders, Opts};
prepare_pipe(Fun, {RecordDecoders, Decoders, Encoders, Opts}, _) when is_function(Fun, 2) ->
    {RecordDecoders, [Fun | Decoders], Encoders, Opts};
prepare_pipe(Fun, _, _) when is_function(Fun) ->
    erlang:error({badpipe, {function_pipe_has_wrong_arity, Fun}});
prepare_pipe(Module, Acc, Pipes) when is_atom(Module) ->
    ok = ensure_loaded(Module),
    IsRecordPipe = erlang:function_exported(Module, decode_record, 3),
    IsPipe = erlang:function_exported(Module, decode, 2),
    case IsRecordPipe orelse IsPipe of
        true -> prepare_module(Module, Acc, Pipes);
        false -> erlang:error({badpipe, {module_does_not_export_decode, Module}})
    end.

prepare_module(Module, {RecordDecoders, Decoders, Encoders, Opts} = Acc, Pipes) ->
    ok = ensure_dependencies(Module, Pipes),
    case maybe_prepare(Module, Opts) of
        disabled ->
            ?LOG_DEBUG(#{what => zone_pipe_disabled, module => Module}, ?LOG_METADATA),
            Acc;
        Opts1 ->
            RecordDecoders1 = maybe_add_fun(Module, decode_record, 3, RecordDecoders),
            Decoders1 = maybe_add_fun(Module, decode, 2, Decoders),
            Encoders1 = maybe_add_fun(Module, encode, 1, Encoders),
            {RecordDecoders1, Decoders1, Encoders1, Opts1}
    end.

maybe_add_fun(Module, Function, Arity, Funs) ->
    case erlang:function_exported(Module, Function, Arity) of
        true -> [fun Module:Function/Arity | Funs];
        false -> Funs
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

%% Every record goes through all the decode_record/3 callbacks before the next record does
run_records(Entries, [], _) ->
    Entries;
run_records([], _, _) ->
    [];
run_records([Source | Sources], RecordDecoders, Opts) ->
    case run_record(RecordDecoders, Source, Source, Opts) of
        drop ->
            run_records(Sources, RecordDecoders, Opts);
        Entry ->
            Entries = run_records(Sources, RecordDecoders, Opts),
            [Entry | Entries]
    end.

run_record([], _, Entry, _) ->
    Entry;
run_record([RecordDecoder | RecordDecoders], Source, Entry, Opts) ->
    case RecordDecoder(Source, Entry, Opts) of
        drop -> drop;
        {error, Reason} -> erlang:error({zone_rejected, RecordDecoder, Reason});
        Next -> run_record(RecordDecoders, Source, Next, Opts)
    end.

run_step(Decoder, {Entries, Opts}) ->
    case Decoder(Entries, Opts) of
        Next when is_list(Next) -> {Next, Opts};
        {Next, NextOpts} when is_list(Next), is_map(NextOpts) -> {Next, NextOpts};
        {error, Reason} -> erlang:error({zone_rejected, Decoder, Reason});
        Other -> erlang:error({bad_zone_pipe_return, Decoder, Other})
    end.

def_opts() ->
    #{zone_name => ~"", version => ~"", scope => zone}.
