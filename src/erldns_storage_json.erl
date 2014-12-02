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

%% Public API
%% @doc Create ets table wrapper. Use match cases for adding different options to the table.
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
%% These tables should always use ets. Due to their functionality
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

%% @doc Insert value in ets table.
-spec insert(atom(), tuple()) -> true | {error, term()}.
insert(Table, Value)->
    ets:insert(Table, Value).


%% @doc Delete entire ets table.
-spec delete_table(atom()) -> true | {error, term()}.
delete_table(Table)->
    ets:delete(Table).

%% @doc Delete an entry in the ets table.
-spec delete(atom(), term()) -> true | {error, term()}.
delete(Table, Key) ->
    ets:delete(Table, Key).

%% @doc Backup a specific ets table.
%% @see https://github.com/SiftLogic/erl-dns/issues/3
-spec backup_table(atom()) -> ok | {error, Reason:: term()}.
backup_table(_Table)->
    ok.

%% @doc Should backup all ets tables.
%% @see https://github.com/SiftLogic/erl-dns/issues/3
-spec backup_tables() -> ok | {error, Reason :: term()}.
backup_tables() ->
    ok.

%% @doc Select from ets using key, value.
-spec select(atom(), term()) -> tuple().
select(Key, Value) ->
    ets:lookup(Key, Value).

%% @doc Select from ets using match specs.
-spec select(atom(), list(), integer()) -> tuple() | '$end_of_table'.
select(Table, MatchSpec, Limit) ->
    ets:select(Table, MatchSpec, Limit).

%% @doc Wrapper for foldl in ets.
-spec foldl(fun(), list(), atom())  -> Acc :: term() | {error, Reason :: term()}.
foldl(Fun, Acc, Table) ->
    ets:foldl(Fun, Acc, Table).

%% @doc Empty ets table.
-spec empty_table(atom()) -> true.
empty_table(Table) ->
    ets:delete_all_objects(Table).
