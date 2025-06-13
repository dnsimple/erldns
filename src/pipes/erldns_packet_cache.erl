-module(erldns_packet_cache).
-moduledoc """
A basic packet cache that is used to avoid multiple lookups for the
same question received within the cache TTL.

In order to work correctly, it should be added to the packet pipeline twice,
once early in the processing pipeline, and once _after_ the resolver.

## Configuration

```erlang
{erldns, [
    {packet_cache, #{
        enabled => boolean(), %% defaults to true
        ttl => non_neg_integer(), %% Seconds, defaults to 30
    }}
]}
```

## Telemetry events

- `[erldns, pipeline, cache]` spans as triggered by `m:segmented_cache`.
""".

-include_lib("dns_erlang/include/dns.hrl").

-behaviour(erldns_pipeline).
-export([prepare/1, call/2]).
-export([start_link/0, clear/0]).

-define(DEFAULT_BUCKETS, 3).
-define(DEFAULT_CACHE_TTL, 30).

-doc "`c:erldns_pipeline:prepare/1` callback.".
-spec prepare(erldns_pipeline:opts()) -> disabled | erldns_pipeline:opts().
prepare(Opts) ->
    case enabled() of
        false -> disabled;
        true -> Opts#{?MODULE => false}
    end.

-doc "`c:erldns_pipeline:call/2` callback.".
-spec call(dns:message(), erldns_pipeline:opts()) -> erldns_pipeline:return().
%% We are authoritative so cache the packet and return the message.
call(#dns_message{aa = true} = Msg, #{?MODULE := miss} = Opts) ->
    Key = {Msg#dns_message.questions, Msg#dns_message.additional},
    segmented_cache:put_entry(?MODULE, Key, Msg),
    {Msg, Opts#{?MODULE := cached}};
call(Msg, #{?MODULE := false} = Opts) ->
    Key = {Msg#dns_message.questions, Msg#dns_message.additional},
    case segmented_cache:get_entry(?MODULE, Key) of
        #dns_message{} = CachedResponse ->
            Msg1 = CachedResponse#dns_message{id = Msg#dns_message.id},
            Opts1 = Opts#{?MODULE := cached, resolved => true},
            {Msg1, Opts1};
        not_found ->
            {Msg, Opts#{?MODULE := miss}}
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
                prefix => [erldns, pipeline, cache],
                scope => erldns,
                segment_num => ?DEFAULT_BUCKETS,
                ttl => {seconds, default_ttl() div ?DEFAULT_BUCKETS}
            },
            segmented_cache:start_link(?MODULE, Config)
    end.

-doc "Clear the cache".
-spec clear() -> any().
clear() ->
    segmented_cache:delete_pattern(?MODULE, '_').

-spec enabled() -> boolean().
enabled() ->
    case application:get_env(erldns, packet_cache, #{}) of
        #{enabled := Bool} when is_boolean(Bool) ->
            Bool;
        _ ->
            true
    end.

-spec default_ttl() -> pos_integer().
default_ttl() ->
    case application:get_env(erldns, packet_cache, #{}) of
        #{ttl := TTL} when is_integer(TTL), 0 < TTL ->
            TTL;
        _ ->
            ?DEFAULT_CACHE_TTL
    end.
