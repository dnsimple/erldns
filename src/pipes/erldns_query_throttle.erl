-module(erldns_query_throttle).
-moduledoc """
Stateful query throttling. Currently only throttles `ANY` queries.

We should_throttle ANY queries to discourage use of our authoritative name servers
for reflection/amplification attacks.

## Configuration

```erlang
{erldns, [
    {query_throttle, #{
        enabled := boolean(), %% defaults to true
        limit := non_neg_integer(), %% Number of queries to allow, defaults to 1
        ttl := non_neg_integer(), %% Seconds, defaults to 30
    }}
]}
```

## Telemetry events

See `m:segmented_cache` for telemetry events under this module name.

Also emits the following telemetry events:
- `[erldns, pipeline, throttle]` with `host` in the metadata.
""".

-include_lib("dns_erlang/include/dns.hrl").

-behaviour(erldns_pipeline).
-export([prepare/1, call/2]).
-export([start_link/0, clear/0, merger/2]).

-type host() :: inet:ip_address() | inet:hostname().

-define(DEFAULT_LIMIT, 1).
-define(DEFAULT_BUCKETS, 3).
-define(DEFAULT_CACHE_TTL, 60).

-spec prepare(erldns_pipeline:opts()) -> disabled | erldns_pipeline:opts().
prepare(Opts) ->
    case enabled() of
        false -> disabled;
        true -> Opts#{packet_throttle_limit => default_limit()}
    end.

-spec call(dns:message(), erldns_pipeline:opts()) -> erldns_pipeline:return().
call(Msg, #{transport := udp, host := Host, packet_throttle_limit := Limit}) ->
    case should_throttle(Msg, Host, Limit) of
        {true, ReqCount} ->
            Metadata = #{transport => udp, host => Host},
            telemetry:execute([erldns, pipeline, throttle], #{count => ReqCount}, Metadata),
            {stop, Msg#dns_message{
                tc = true,
                aa = true,
                rc = ?DNS_RCODE_NOERROR
            }};
        false ->
            Msg
    end;
call(Msg, _) ->
    Msg.

-doc false.
-spec start_link() -> any().
start_link() ->
    case enabled() of
        false ->
            ignore;
        true ->
            Config = #{
                scope => erldns,
                strategy => lru,
                merger_fun => fun ?MODULE:merger/2,
                segment_num => ?DEFAULT_BUCKETS,
                ttl => {seconds, default_ttl() div ?DEFAULT_BUCKETS}
            },
            segmented_cache:start_link(?MODULE, Config)
    end.

-spec should_throttle(dns:message(), host(), non_neg_integer()) ->
    false | {true, non_neg_integer()}.
should_throttle(Msg, Host, Limit) ->
    HasAny = lists:any(
        fun(#dns_query{type = T}) -> T =:= ?DNS_TYPE_ANY end, Msg#dns_message.questions
    ),
    HasAny andalso should_throttle(Host, Limit).

-spec should_throttle(host(), non_neg_integer()) -> false | {true, non_neg_integer()}.
should_throttle({127, 0, 0, 1}, _) ->
    false;
should_throttle({0, 0, 0, 0, 0, 0, 0, 1}, _) ->
    false;
should_throttle(Host, Limit) ->
    case segmented_cache:get_entry(?MODULE, Host) of
        not_found ->
            segmented_cache:put_entry(?MODULE, Host, 1),
            false;
        ReqCount when is_integer(ReqCount), ReqCount < Limit ->
            segmented_cache:put_entry(?MODULE, Host, ReqCount),
            false;
        ReqCount when is_integer(ReqCount), ReqCount >= Limit ->
            segmented_cache:put_entry(?MODULE, Host, ReqCount),
            {true, ReqCount}
    end.

-doc "Clear the cache".
-spec clear() -> any().
clear() ->
    segmented_cache:delete_pattern(?MODULE, '_').

-doc false.
-spec merger(non_neg_integer(), non_neg_integer()) -> non_neg_integer().
merger(_A, B) ->
    B + 1.

-spec enabled() -> boolean().
enabled() ->
    case application:get_env(erldns, query_throttle, #{}) of
        #{enabled := Value} when is_boolean(Value) ->
            Value;
        _ ->
            true
    end.

-spec default_limit() -> pos_integer().
default_limit() ->
    case application:get_env(erldns, query_throttle, #{}) of
        #{limit := Value} when is_integer(Value), 0 < Value ->
            Value;
        _ ->
            ?DEFAULT_LIMIT
    end.

-spec default_ttl() -> pos_integer().
default_ttl() ->
    case application:get_env(erldns, query_throttle, #{}) of
        #{ttl := Value} when is_integer(Value), 0 < Value ->
            Value;
        _ ->
            ?DEFAULT_CACHE_TTL
    end.
