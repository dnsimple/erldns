-module(erldns_pipeline).
-moduledoc """
The pipeline specification.

It declares a pipeline of sequential transformations to apply to the
incoming query until a response is constructed.

This module is responsible for handling the pipeline of pipes that will be
executed when a DNS message is received. Handlers in this pipeline will be
executed sequentially, accumulating the result of each handler and passing
it to the next. This designs a pluggable framework where new behaviour can
be injected as a new pipe handler in the right order.

## Default pipes

The following are enabled by default, see their documentation for details:

- `m:erldns_questions`
- `m:erldns_edns_max_payload_size`
- `m:erldns_query_throttle`
- `m:erldns_packet_cache`
- `m:erldns_resolver_recursive`
- `m:erldns_resolver`
- `m:erldns_dnssec`
- `m:erldns_sorter`
- `m:erldns_section_counter`
- `m:erldns_empty_verification`

## Types of pipelines

There are two kind of pipes: function pipes and module pipes.

### Function pipes

A function pipe is by definition any function that receives a `t:dns:message/0`
and a set of options and returns a `t:dns:message/0`. Function pipes must have
the following type signature:

```erlang
-type pipe() :: fun((dns:message(), opts()) -> return()
```

### Module pipes

The preferred mechanism, a module pipe is an extension of the function pipe.

It is a module that exports:
* a `c:prepare/1` function which takes a set of options and initializes it, or disables the pipe.
* a `c:call/2` function with the signature defined as in the function pipe.

The API expected by a module pipe is defined as a behaviour by this module.

## Configuration

```erlang
{erldns, [
    {packet_pipeline, [
        erldns_questions,
        erldns_edns_max_payload_size,
        erldns_query_throttle,
        erldns_packet_cache,
        erldns_resolver_recursive,
        erldns_resolver,
        erldns_dnssec,
        erldns_sorter,
        erldns_section_counter,
        erldns_packet_cache,
        erldns_empty_verification
    ]},
]}
```

## Telemetry events

Emits the following telemetry events:

### `[erldns, pipeline, error]`
- Measurements:
```erlang
count := non_neg_integer()
```
- Metadata:
If it is an exception, the metadata will contain:
```erlang
kind => exit | error | throw
reason => term()
stacktrace => [term()]
```
otherwise, it will contain:
```erlang
reason => term()
```

## Examples

Here's an example of a function pipe that arbitrarily sets the truncated bit
on a message if the query is directed to the "example.com" domain:

```erlang
-module(erldns_packet_pipe_example_set_truncated).
-behaviour(erldns_pipeline).

-export([prepare/1, call/2]).

-spec prepare(erldns_pipeline:opts()) -> disabled | erldns_pipeline:opts().
prepare(Opts) ->
    case enabled() of
        false -> disabled;
        true -> Opts
    end.

-spec call(dns:message(), erldns_pipeline:opts()) -> erldns_pipeline:return().
call(#dns_message{questions = [#dns_query{name = <<"example.com">>} | _]} = Msg, _Opts) ->
    Msg#dns_message{tc = true}.
call(Msg, _Opts) ->
    Msg.
```
""".

-include_lib("dns_erlang/include/dns.hrl").
-include_lib("kernel/include/logger.hrl").

-doc "The host that originated the request.".
-type host() :: inet:ip_address() | inet:hostname().

-doc "The underlying request transport protocol. All requests come either through UDP or TCP.".
-type transport() :: tcp | udp.

-doc "Options that can be passed and accumulated to the pipeline.".
-type opts() :: #{
    query_labels := dns:labels(),
    query_type := dns:type(),
    monotonic_time := integer(),
    resolved := boolean(),
    transport := transport(),
    port := inet:port_number(),
    host := host(),
    socket := gen_tcp:socket() | {gen_udp:socket(), inet:port_number()},
    atom() => dynamic()
}.

-doc """
The return type of a pipe.

It can return `halt`, a new `t:dns:message/0`, with or without new `t:opts/0`,
or put a `stop` to the pipeline execution.
""".
-type return() :: halt | dns:message() | {dns:message(), opts()} | {stop, dns:message()}.

-doc """
The dependencies of a pipe module.

Contains the following keys:
- `prerequisites` is a list of module pipes that must appear earlier in the pipeline
- `dependents` is a list of module pipes that must appear later in the pipeline
""".
-type deps() :: #{prerequisites => [module()], dependents => [module()]}.

-doc """
A pipe in the pipeline, either a module or a function.

See [Module pipes](#module-module-pipes) and [Function pipes](#module-function-pipes) for details.
""".
-type pipe() :: module() | fun((dns:message(), opts()) -> return()).

-type pipeline() :: [fun((dns:message(), opts()) -> return())].

-export_type([transport/0, host/0, pipe/0, opts/0, deps/0, return/0]).

-doc """
Initialise the pipe handler, triggering side-effects and preparing any necessary metadata.

This will be called during the pipeline initialisation phase, which should happen at application
startup provided you added the pipeline to your application's supervision tree. This will be called
only once during application startup and therefore it is an opportunity to do any necessary
preparations that can reduce the amount of work at runtime and therefore improve performance.

This callback can return `disabled`, and then the `c:call/2` callback won't be added to the
pipeline.
""".
-callback prepare(opts()) -> disabled | opts().

-doc """
Trigger the pipeline at run-time.

This callback can return
- a possibly new `t:dns:message/0`;
- a tuple containing a new `t:dns:message/0` and a new set of `t:opts/0`;
- a `{stop, t:dns:message/0}` tuple to stop the pipeline execution altogether.
- a `halt` atom, in which case the pipeline will be halted and no further pipes will be executed.
    The socket workers won't respond nor trigger any events, and it's fully the responsibility of
    a handler to deal with all the edge cases. This could be useful for either dropping the request
    entirely, or for stealing the request from a given worker to answer separately.
    Note that the pipe options will contain the UDP or TCP socket to answer to, so in the case
    of UDP the client can be answered using `gen_udp:send/4` with the socket, host and port;
    and in the case of TCP it would be required to first steal the socket using
    `gen_tcp:controlling_process/2` so that the connection is not closed.
""".
-callback call(dns:message(), opts()) ->
    halt | dns:message() | {dns:message(), opts()} | {stop, dns:message()}.
-doc """
Declare dependencies on other pipes.

This pipe will only work correctly if the listed pipes appear earlier in the pipeline configuration.
The pipeline will fail to start if dependencies are not satisfied.

Example:
```erlang
-module(erldns_dnssec).
-behaviour(erldns_pipeline).
-export([deps/0, prepare/1, call/2]).

-spec deps() -> deps().
deps() ->
    #{prerequisites => [erldns_questions, erldns_resolver], dependents => []}.
```
""".
-callback deps() -> deps().

-optional_callbacks([prepare/1, deps/0]).

-behaviour(supervisor).

-export([call/2, call_custom/3, store_pipeline/2, delete_pipeline/1]).
-export([is_pipe_configured/1, is_pipe_configured/2]).
-export([start_link/0, init/1, store_pipeline/0]).

-ifdef(TEST).
-export([def_opts/0]).
-else.
-compile({inline, [def_opts/0]}).
-endif.

-define(DEFAULT_PACKET_PIPELINE, [
    erldns_questions,
    erldns_edns_max_payload_size,
    erldns_query_throttle,
    erldns_packet_cache,
    erldns_resolver_recursive,
    erldns_resolver,
    erldns_dnssec,
    erldns_sorter,
    erldns_section_counter,
    erldns_packet_cache,
    erldns_empty_verification
]).

-define(LOG_METADATA, #{domain => [erldns, pipeline]}).

-doc """
Call the main application packet pipeline with the pipes configured in the system configuration.
""".
-spec call(dns:message(), #{atom() => dynamic()}) -> halt | dns:message().
call(Msg, Opts) ->
    ?LOG_DEBUG(
        #{what => main_pipeline_triggered, dns_message => Msg, opts => Opts},
        ?LOG_METADATA
    ),
    {Pipeline, DefOpts} = get_pipeline(),
    do_call(Msg, Pipeline, maps:merge(DefOpts, Opts)).

-doc """
Call a custom pipeline by name.

The pipeline should have been verifiend and stored previously with `store_pipeline/2`.
""".
-spec call_custom(dns:message(), #{atom() => dynamic()}, dynamic()) -> halt | dns:message().
call_custom(Msg, Opts, PipelineName) ->
    ?LOG_DEBUG(
        #{
            what => custom_pipeline_triggered,
            name => PipelineName,
            dns_message => Msg,
            opts => Opts
        },
        ?LOG_METADATA
    ),
    {Pipeline, DefOpts} = get_pipeline(PipelineName),
    do_call(Msg, Pipeline, maps:merge(DefOpts, Opts)).

-doc """
Verify and store a custom pipeline.

Can be used to prepare a custom pipeline that can be triggered using `call_custom/3`.

Validates that pipe dependencies (declared via `c:deps/0`) are satisfied by the given order.
Raises an error if a pipe's dependencies don't appear earlier in the pipeline.
""".
-spec store_pipeline(term(), [pipe()]) -> ok.
store_pipeline(PipelineName, Pipes) ->
    {Pipeline, Opts} = validate_and_prepare(Pipes),
    persistent_term:put(PipelineName, {lists:reverse(Pipeline), Opts}).

-doc """
Remove a custom pipeline from storage.

Should be used to clean up a custom pipeline stored with `store_pipeline/2`.
""".
-spec delete_pipeline(term()) -> boolean().
delete_pipeline(PipelineName) ->
    persistent_term:erase(PipelineName).

-doc "Check if a pipe is configured in the main pipeline.".
-spec is_pipe_configured(pipe()) -> boolean().
is_pipe_configured(Pipe) ->
    is_pipe_configured(Pipe, ?MODULE).

-doc """
Check if a pipe is configured in a specific pipeline. Returns `false` if the pipeline doesn't exist.
""".
-spec is_pipe_configured(pipe(), term()) -> boolean().
is_pipe_configured(Module, PipelineName) when is_atom(Module) ->
    is_pipe_configured(fun Module:call/2, PipelineName);
is_pipe_configured(Fun, PipelineName) when is_function(Fun, 2) ->
    case persistent_term:get(PipelineName, undefined) of
        undefined ->
            false;
        {Pipeline, _Opts} ->
            lists:member(Fun, Pipeline)
    end.

-spec do_call(dns:message(), pipeline(), opts()) -> halt | dns:message().
do_call(Msg, [Pipe | Pipes], Opts) when is_function(Pipe, 2) ->
    try Pipe(Msg, Opts) of
        halt ->
            halt;
        #dns_message{} = Msg1 ->
            do_call(Msg1, Pipes, Opts);
        {#dns_message{} = Msg1, Opts1} ->
            do_call(Msg1, Pipes, Opts1);
        {stop, #dns_message{} = Msg1} ->
            Msg1;
        Other ->
            telemetry:execute([erldns, pipeline, error], #{count => 1}, #{reason => Other}),
            ?LOG_ERROR(
                #{
                    what => pipe_failed_with_invalid_return,
                    pipe => Pipe,
                    dns_message => Msg,
                    opts => Opts,
                    unexpected_return => Other
                },
                ?LOG_METADATA
            ),
            do_call(Msg, Pipes, Opts)
    catch
        Class:Error:Stacktrace ->
            ExceptionMetadata = #{kind => Class, reason => Error, stacktrace => Stacktrace},
            telemetry:execute([erldns, pipeline, error], #{count => 1}, ExceptionMetadata),
            ?LOG_ERROR(
                #{
                    what => pipe_failed_with_exception,
                    pipe => Pipe,
                    dns_message => Msg,
                    opts => Opts,
                    class => Class,
                    error => Error,
                    stacktrace => Stacktrace
                },
                ?LOG_METADATA
            ),
            do_call(Msg, Pipes, Opts)
    end;
do_call(Msg, [], _) ->
    Msg.

-doc false.
-spec start_link() -> gen_server:start_ret().
start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, noargs).

-doc false.
-spec init(noargs) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init(noargs) ->
    SupFlags = #{strategy => one_for_one, intensity => 20, period => 10},
    Children =
        [
            worker(erldns_pg, pg, [erldns]),
            worker(erldns_packet_cache),
            worker(erldns_query_throttle),
            worker(erldns_handler),
            worker(erldns_pipeline_worker)
        ],
    {ok, {SupFlags, Children}}.

worker(Module) ->
    worker(Module, Module, []).

worker(Name, Module, Args) ->
    #{id => Name, start => {Module, start_link, Args}, type => worker}.

-spec get_pipeline() -> {pipeline(), opts()}.
get_pipeline() ->
    persistent_term:get(?MODULE).

-spec get_pipeline(term()) -> {pipeline(), opts()}.
get_pipeline(PipelineName) ->
    persistent_term:get(PipelineName).

-doc false.
-spec store_pipeline() -> ok.
store_pipeline() ->
    Pipes = application:get_env(erldns, packet_pipeline, ?DEFAULT_PACKET_PIPELINE),
    store_pipeline(?MODULE, Pipes).

-doc """
Validate dependencies and prepare all pipes.

For each pipe, checks if it exports `c:deps/0`, and if so, validates that
all dependencies appear earlier in the pipeline.
""".
-spec validate_and_prepare([pipe()]) -> {pipeline(), opts()}.
validate_and_prepare(Pipes) ->
    Init = {[], def_opts()},
    {Result, _} = lists:foldl(fun prepare_pipe/2, {Init, Pipes}, Pipes),
    Result.

-doc "Prepare a pipe and validate its dependencies.".
-spec prepare_pipe(pipe(), {{pipeline(), opts()}, [pipe()]}) -> {{pipeline(), opts()}, [pipe()]}.
prepare_pipe(Module, {{Pipeline, Opts}, OriginalPipes}) when is_atom(Module) ->
    maybe
        ok ?= ensure_module_loaded(Module),
        ok ?= ensure_exports_call(Module),
        ok ?= ensure_dependencies(Module, OriginalPipes),
        disabled ?= maybe_prepare(Module, Opts),
        ?LOG_WARNING(#{what => pipe_disabled, module => Module}, ?LOG_METADATA),
        {{Pipeline, Opts}, OriginalPipes}
    else
        {enabled, NewOpts} ->
            {{[fun Module:call/2 | Pipeline], NewOpts}, OriginalPipes};
        {error, Reason} ->
            erlang:error({badpipe, Reason})
    end;
prepare_pipe(Fun, {{Pipeline, Opts}, OriginalPipes}) when is_function(Fun, 2) ->
    {{[Fun | Pipeline], Opts}, OriginalPipes};
prepare_pipe(Fun, _) when is_function(Fun) ->
    erlang:error({badpipe, {function_pipe_has_wrong_arity, Fun}}).

-doc "Ensure a module can be loaded.".
-spec ensure_module_loaded(module()) -> ok | {error, dynamic()}.
ensure_module_loaded(Module) ->
    case code:ensure_loaded(Module) of
        {module, Module} -> ok;
        {error, Reason} -> {error, {module, Reason}}
    end.

-doc "Ensure module exports call/2.".
-spec ensure_exports_call(module()) -> ok | {error, dynamic()}.
ensure_exports_call(Module) ->
    case erlang:function_exported(Module, call, 2) of
        true -> ok;
        false -> {error, {module_does_not_export_call, Module}}
    end.

-doc "Check if module declares dependencies and validate them.".
-spec ensure_dependencies(module(), [pipe()]) -> ok | {error, dynamic()}.
ensure_dependencies(Module, OriginalPipes) ->
    case erlang:function_exported(Module, deps, 0) of
        true ->
            Deps = Module:deps(),
            validate_deps_satisfied(Module, OriginalPipes, Deps);
        false ->
            ok
    end.

-spec maybe_prepare(module(), opts()) -> disabled | {enabled, opts()} | {error, dynamic()}.
maybe_prepare(Module, Opts) ->
    case erlang:function_exported(Module, prepare, 1) andalso Module:prepare(Opts) of
        disabled -> disabled;
        false -> {enabled, Opts};
        Opts1 when is_map(Opts1) -> {enabled, Opts1};
        _Other -> {error, {module_init_returned_non_map, Module}}
    end.

-doc "Validate that all declared dependencies appear earlier in the pipeline.".
-spec validate_deps_satisfied(atom(), [pipe()], deps()) -> ok | {error, dynamic()}.
validate_deps_satisfied(Module, OriginalPipes, Deps) ->
    % "Before" can only be empty if the module is the first in the pipeline
    % "After" can only be empty if the module was never in the pipeline,
    % which is impossible, otherwise "After" always starts with the module itself
    {ModulesDefinedBefore, [Module | ModulesDefinedAfter]} =
        lists:splitwith(fun(P) -> P =/= Module end, OriginalPipes),
    Prerequisites = maps:get(prerequisites, Deps, []),
    Dependents = maps:get(dependents, Deps, []),
    DepHint = ~"Prerequisite must appear earlier in pipeline",
    PreHint = ~"Dependent must appear earlier in pipeline",
    PreSafisfied = ensure_satisfied(Module, ModulesDefinedBefore, PreHint, Prerequisites),
    DepSafisfied = ensure_satisfied(Module, ModulesDefinedAfter, DepHint, Dependents),
    case {PreSafisfied, DepSafisfied} of
        {true, true} -> ok;
        {{error, Reason}, _} -> {error, Reason};
        {_, {error, Reason}} -> {error, Reason}
    end.

ensure_satisfied(Module, ModulesDefinedBefore, Hint, List) ->
    Fun = fun(Requires, _) ->
        lists:member(Requires, ModulesDefinedBefore) orelse
            {error,
                {unsatisfied_dependency, #{
                    pipe => Module,
                    requires => Requires,
                    hint => Hint
                }}}
    end,
    lists:foldl(Fun, true, List).

def_opts() ->
    #{
        query_labels => [],
        query_type => ?DNS_TYPE_A,
        monotonic_time => 0,
        resolved => false,
        transport => udp,
        port => undefined,
        host => undefined,
        socket => undefined
    }.
