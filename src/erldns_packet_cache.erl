%% Copyright (c) 2012-2020, DNSimple Corporation
%%
%% Permission to use, copy, modify, and/or distribute this software for any
%% purpose with or without fee is hereby granted, provided that the above
%% copyright notice and this permission notice appear in all copies.
%%
%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
%% WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
%% MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
%% ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
%% WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
%% ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
%% OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

-module(erldns_packet_cache).
-moduledoc """
A basic packet cache that is used to avoid multiple lookups for the
same question received within the cache TTL.

The cache is swept for old cache data at regular intervals.

## Configuration

```erlang
{erldns, [
    {packet_cache, #{
        enabled := boolean(), %% defaults to true
        ttl := non_neg_integer(), %% Seconds, defaults to 30
    }}
]}
```

## Telemetry events

See `m:segmented_cache` for telemetry events. The name is `erldns_cache`.
""".

-include_lib("dns_erlang/include/dns.hrl").

-export([
    start_link/0,
    get/1,
    get/2,
    put/2,
    clear/0
]).

-define(NAME, erldns_cache).
-define(DEFAULT_CACHE_TTL, 30).

-doc false.
-spec start_link() -> any().
start_link() ->
    Config = #{
        scope => erldns,
        segment_num => 3,
        ttl => {seconds, packet_cache_default_ttl() div 3}
    },
    segmented_cache:start_link(?NAME, Config).

-doc "Try to retrieve a cached response for the given question.".
-spec get(dns:questions() | {dns:questions(), dns:additional()}) ->
    dns:message() | {error, cache_expired | cache_miss}.
get(Key) ->
    get(Key, undefined).

-doc "Try to retrieve a cached response for the given question sent by the given host.".
-spec get(dns:questions() | {dns:questions(), dns:additional()}, undefined | inet:ip_address()) ->
    dns:message() | {error, cache_expired | cache_miss}.
get(Key, _Host) ->
    case segmented_cache:get_entry(?NAME, Key) of
        #dns_message{} = Value ->
            Value;
        not_found ->
            {error, cache_miss}
    end.

-doc "Put the response in the cache for the given question.".
-spec put({dns:questions(), dns:additional()}, dns:message()) -> boolean().
put(Key, Response) ->
    case packet_cache_enabled() of
        true ->
            segmented_cache:put_entry(?NAME, Key, Response);
        false ->
            false
    end.

-doc "Clear the cache".
-spec clear() -> any().
clear() ->
    segmented_cache:delete_pattern(?NAME, '_').

-spec packet_cache_enabled() -> boolean().
packet_cache_enabled() ->
    case application:get_env(erldns, packet_cache, #{}) of
        #{enabled := Bool} when is_boolean(Bool) ->
            Bool;
        _ ->
            true
    end.

-spec packet_cache_default_ttl() -> pos_integer().
packet_cache_default_ttl() ->
    case application:get_env(erldns, packet_cache, #{}) of
        #{ttl := TTL} when is_integer(TTL), 0 < TTL ->
            TTL;
        _ ->
            ?DEFAULT_CACHE_TTL
    end.
