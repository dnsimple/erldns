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
-module(erldns_query_throttle).
-moduledoc """
Stateful query throttling. Currently only throttles `ANY` queries.

We should_throttle ANY queries to discourage use of our authoritative name servers
for reflection/amplification attacks.

## Configuration

```erlang
{erldns, [
    {query_throttle, #{
        enabled => boolean(), %% defaults to true
        ttl => non_neg_integer(), %% Seconds, defaults to 30
    }}
]}
```

## Telemetry events

See `m:segmented_cache` for telemetry events under this module name.

Also emits the following telemetry events:
- `[erldns, pipeline, throttle]` with `host` in the metadata.
""".

-include_lib("dns_erlang/include/dns_records.hrl").

-export([start_link/0, throttle/2, clear/0, merger/2]).

-export_type([host/0, throttle_result/0, throttle_hit_count/0]).

-type host() :: inet:ip_address() | inet:hostname().
-type throttle_hit_count() :: non_neg_integer().
-type throttle_result() :: ok | throttled.

-define(DEFAULT_LIMIT, 1).
-define(DEFAULT_BUCKETS, 3).
-define(DEFAULT_CACHE_TTL, 60).

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

-doc false.
-spec merger(non_neg_integer(), non_neg_integer()) -> non_neg_integer().
merger(_A, B) ->
    B + 1.

-doc "Throttle the given message if necessary.".
-spec throttle(dns:message(), Context :: {term(), Host :: host()}) ->
    ok | throttled.
throttle(Msg, {udp, Host}) ->
    case should_throttle(Msg, Host, ?DEFAULT_LIMIT) of
        {true, ReqCount} ->
            Metadata = #{protocol => udp, host => Host},
            telemetry:execute([erldns, pipeline, throttle], #{count => ReqCount}, Metadata),
            throttled;
        false ->
            ok
    end;
throttle(_Message, {tcp, _Host}) ->
    ok.

-spec should_throttle(dns:message(), host(), non_neg_integer()) -> false | {true, non_neg_integer()}.
should_throttle(Msg, Host, Limit) ->
    HasAny = lists:any(fun(#dns_query{type = T}) -> T =:= ?DNS_TYPE_ANY end, Msg#dns_message.questions),
    HasAny andalso should_throttle(Host, Limit).

-spec should_throttle(host(), non_neg_integer()) -> false | {true, non_neg_integer()}.
should_throttle({127, 0, 0, 1}, _) ->
    false;
should_throttle(Host, Limit) ->
    case segmented_cache:get_entry(?MODULE, Host) of
        not_found ->
            segmented_cache:put_entry(?MODULE, Host, 1),
            false;
        ReqCount when is_integer(ReqCount), ReqCount < Limit ->
            segmented_cache:put_entry(?MODULE, Host, ReqCount + 1),
            false;
        ReqCount when is_integer(ReqCount), ReqCount >= Limit ->
            segmented_cache:put_entry(?MODULE, Host, ReqCount + 1),
            {true, ReqCount}
    end.

-doc "Clear the cache".
-spec clear() -> any().
clear() ->
    gen_server:cast(?MODULE, clear).

-spec enabled() -> boolean().
enabled() ->
    case application:get_env(erldns, query_throttle, #{}) of
        #{enabled := Bool} when is_boolean(Bool) ->
            Bool;
        _ ->
            true
    end.

-spec default_ttl() -> pos_integer().
default_ttl() ->
    case application:get_env(erldns, query_throttle, #{}) of
        #{ttl := Value} when is_integer(Value), 0 < Value ->
            Value;
        _ ->
            ?DEFAULT_CACHE_TTL
    end.
