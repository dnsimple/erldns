# The pipeline specification

It declares a pipeline of sequential transformations to apply to an
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
and a set of `t:opts/0` options and returns a `t:dns:message/0`. Function pipes
must have the following type signature:

```erlang
-type pipefun() :: fun((dns:message(), erldns_pipeline:opts()) -> erldns_pipeline:return())
```

### Module pipes

The preferred mechanism, a module pipe is an extension of the function pipe.

It is a module that exports:

- a `c:deps/0` function which enumerates pipes required to run before or after the current pipe.
- a `c:prepare/1` function which takes a set of options and initializes it, or disables the pipe.
- a `c:call/2` function with the signature defined as in the function pipe.

The API expected by a module pipe is defined as a behaviour by this module.

## Suspending Pipes

A pipe can suspend execution to perform blocking work asynchronously. This is
useful for operations like external DNS resolution that would block the worker.

To suspend, return `{suspend, Msg1, Opts1, AsyncFun}` from your pipe:

```erlang
-spec call(dns:message(), erldns_pipeline:opts()) -> erldns_pipeline:return().
call(Msg, Opts) ->
    case needs_external_resolution(Msg) of
        false ->
            Msg;
        true ->
            AsyncFun = fun(M, _O, _Ctx) ->
                %% This runs in the async pool, blocking is OK here
                resolve_external(M)
            end,
            {suspend, Msg, Opts, AsyncFun}
    end.
```

The asynchronous function behaves like a regular pipe function, and it can even return more
asynchronous work. Once work is not asynchronous anymore, the remaining of the pipeline will
be scheduled back in the regular worker.

## Async pool

When a pipe suspends, the blocking work is run in a bounded worker pool so that
listener workers are not blocked.

Pool behaviour:

- Uses a worker pool (wpool) with CoDel for queue management.
- Default parallelism: 4x. Configurable via `pipeline` options below.
- Pool size and pending task counts are available for monitoring via the pool implementation.

## Configuration

### Packet pipeline (list of pipes)

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

### Pipeline async pool (size and CoDel)

```erlang
{erldns, [
    {pipeline, #{
        async_pool => #{
          parallelism => 32,       % Worker count (default: 4 * schedulers)
          codel_interval => 500,   % CoDel interval in ms (default: 500)
          codel_target => 50       % CoDel target delay in ms (default: 50)
        }
      }
    }
]}
```

## Telemetry events

### `[erldns, pipeline, error]`

Emitted when pipeline execution hits an error: invalid pipe return,
exception in a pipe, exception in async work, or suspend loop detection.

- **Measurements:** `#{count => 1}`
- **Metadata (exception in sync or async pipe):**

  ```erlang
  kind => exit | error | throw
  reason => term()
  stacktrace => [term()]
  ```

- **Metadata (invalid return from pipe):** `#{reason => term()}`
- **Metadata (too many nested suspends):** `#{reason => pipeline_suspend_loop}`
- **Metadata (exception in async pool worker):** `#{what => async_work_failed, class => ..., reason => ..., stacktrace => ...}`

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
call(#dns_message{questions = [#dns_query{name = ~"example.com"} | _]} = Msg, _Opts) ->
    Msg#dns_message{tc = true}.
call(Msg, _Opts) ->
    Msg.
```
