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
    host := host(),
    atom() => dynamic()
}.
-type return() :: dns:message() | {dns:message(), opts()} | {stop, dns:message()}.
-type pipe() :: module() | fun((dns:message(), opts()) -> return()).
-type pipeline() :: [fun((dns:message(), opts()) -> return())].
-export_type([transport/0, host/0, pipe/0, opts/0, return/0]).

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
- a tuple `{stop, t:dns:message/0}` tuple to stop the pipeline execution altogether.
""".
-callback call(dns:message(), opts()) ->
    dns:message() | {dns:message(), opts()} | {stop, dns:message()}.
-optional_callbacks([prepare/1]).

-behaviour(supervisor).

-export([call/2]).
-export([start_link/0, init/1]).
-export([store_pipeline/0]).
-ifdef(TEST).
-export([def_opts/0]).
-else.
-compile({inline, [def_opts/0]}).
-endif.

-define(DEFAULT_PACKET_PIPELINE, [
    erldns_questions,
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

-spec call(dns:message(), #{atom() => dynamic()}) -> dns:message().
call(Msg, Opts) ->
    ?LOG_DEBUG(
        #{what => pipeline_triggered, dns_message => Msg, opts => Opts},
        #{domain => [erldns, pipeline]}
    ),
    {Pipeline, DefOpts} = get_pipeline(),
    do_call(Msg, Pipeline, maps:merge(DefOpts, Opts)).

-spec do_call(dns:message(), pipeline(), opts()) -> dns:message().
do_call(Msg, [Pipe | Pipes], Opts) when is_function(Pipe, 2) ->
    try Pipe(Msg, Opts) of
        #dns_message{} = Msg1 ->
            do_call(Msg1, Pipes, Opts);
        {#dns_message{} = Msg1, Opts1} ->
            do_call(Msg1, Pipes, Opts1);
        {stop, #dns_message{} = Msg1} ->
            Msg1;
        Other ->
            telemetry:execute([erldns, pipeline, error], #{count => 1}, #{}),
            ?LOG_ERROR(
                #{
                    what => pipe_failed_with_invalid_return,
                    pipe => Pipe,
                    dns_message => Msg,
                    opts => Opts,
                    unexpected_return => Other
                },
                #{domain => [erldns, pipeline]}
            ),
            do_call(Msg, Pipes, Opts)
    catch
        Class:Error:Stacktrace ->
            telemetry:execute([erldns, pipeline, error], #{count => 1}, #{}),
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
                #{domain => [erldns, pipeline]}
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

-doc false.
-spec store_pipeline() -> ok.
store_pipeline() ->
    Pipes = application:get_env(erldns, packet_pipeline, ?DEFAULT_PACKET_PIPELINE),
    {Pipeline, Opts} = lists:foldl(fun prepare_pipe/2, {[], def_opts()}, Pipes),
    persistent_term:put(?MODULE, {lists:reverse(Pipeline), Opts}).

-spec prepare_pipe(pipe(), {pipeline(), opts()}) -> {pipeline(), opts()}.
prepare_pipe(Module, {Pipeline, Opts}) when is_atom(Module) ->
    maybe
        {module, Module} ?= code:ensure_loaded(Module),
        true ?= erlang:function_exported(Module, call, 2),
        false ?= erlang:function_exported(Module, prepare, 1),
        {[fun Module:call/2 | Pipeline], Opts}
    else
        {error, Reason} ->
            erlang:error({badpipe, {module, Reason}});
        false ->
            erlang:error({badpipe, module_does_not_export_call});
        true ->
            case Module:prepare(Opts) of
                disabled ->
                    ?LOG_WARNING(
                        #{what => pipe_disabled, module => Module},
                        #{domain => [erldns, pipeline]}
                    ),
                    {Pipeline, Opts};
                Opts1 when is_map(Opts1) ->
                    {[fun Module:call/2 | Pipeline], Opts1};
                _ ->
                    erlang:error({badpipe, {module_init_returned_non_map, Module}})
            end
    end;
prepare_pipe(Fun, {Pipeline, Opts}) when is_function(Fun, 2) ->
    {[Fun | Pipeline], Opts};
prepare_pipe(Fun, _) when is_function(Fun) ->
    erlang:error({badpipe, {function_pipe_has_wrong_arity, Fun}}).

def_opts() ->
    #{
        query_labels => [],
        query_type => ?DNS_TYPE_A,
        monotonic_time => 0,
        resolved => false,
        transport => udp,
        host => undefined
    }.
