%% Copyright (c) 2014, SiftLogic LLC
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

-module(erldns_storage_json).

%% API
-export([create/1,
    insert/2,
    delete_table/1,
    delete/2,
    backup_table/1,
    backup_tables/0,
    select/2,
    select/3,
    foldl/3,
    empty_table/1]).

-spec create(atom()) -> ok.
create(zones) ->
    case ets:info(zones) of
        undefined ->
               zones = ets:new(zones, [set, public, named_table]);
        _InfoList ->
            ok
    end;
create(authorities) ->
    case ets:info(authorities) of
        undefined ->
            authorities = ets:new(authorities, [set, public, named_table]);
        _InfoList ->
            ok
    end;
%% These tables should always use ets.
create(packet_cache) ->
    case ets:info(packet_cache) of
        undefined ->
            packet_cache = ets:new(packet_cache, [set, public, named_table]);
        _InfoList ->
            ok
    end;
create(host_throttle) ->
    case ets:info(host_throttle) of
        undefined ->
            host_throttle = ets:new(host_throttle, [set, public, named_table]);
        _InfoList ->
            ok
    end;
create(handler_registry) ->
    case ets:info(handler_registry) of
        undefined ->
            handler_registry = ets:new(handler_registry, [set, public, named_table]);
        _InfoList ->
            ok
    end.

-spec insert(atom(), tuple()) -> ok.
insert(Table, Value)->
    true = ets:insert(Table, Value),
    ok.

-spec delete_table(atom()) -> true.
delete_table(Table)->
    true = ets:delete(Table),
    ok.

-spec delete(atom(), term()) -> true.
delete(Table, Key) ->
    true = ets:delete(Table, Key),
    ok.

-spec backup_table(atom()) -> ok | {error, Reason:: term()}.
backup_table(_Table)->
    ok.

-spec backup_tables() -> ok | {error, Reason :: term()}.
backup_tables() ->
    ok.

-spec select(atom(), term()) -> tuple().
select(Key, Value) ->
    ets:lookup(Key, Value).

-spec select(atom(), list(), integer()) -> tuple() | '$end_of_table'.
select(Table, MatchSpec, Limit) ->
    ets:select(Table, MatchSpec, Limit).

-spec foldl(fun(), list(), atom())  -> Acc :: term() | {error, Reason :: term()}.
foldl(Fun, Acc, Table) ->
    ets:foldl(Fun, Acc, Table).

-spec empty_table(atom()) -> ok.
empty_table(Table) ->
    ets:delete_all_objects(Table).
