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
         empty_table/1,
         list_table/1]).

%% Public API
%% @doc Create ets table wrapper. Use match cases for adding different options to the table.
-spec create(atom()) -> ok | {error, Reason :: term()}.
create(zones) ->
    case ets:info(zones) of
        undefined ->
            case ets:new(zones, [set, public, named_table]) of
                zones ->
                    ok;
                Error ->
                    {error, Error}
            end;
        _InfoList ->
            ok
    end;
create(authorities) ->
    case ets:info(authorities) of
        undefined ->
            case ets:new(authorities, [set, public, named_table]) of
                authorities ->
                    ok;
                Error ->
                    {error, Error}
            end;
        _InfoList ->
            ok
    end;
%% These tables should always use ets. Due to their functionality
create(packet_cache) ->
    case ets:info(packet_cache) of
        undefined ->
            case ets:new(packet_cache, [set, public, named_table]) of
                packet_cache ->
                    ok;
                Error ->
                    {error, Error}
            end;
        _InfoList ->
            ok
    end;
create(host_throttle) ->
    case ets:info(host_throttle) of
        undefined ->
            case ets:new(host_throttle, [set, public, named_table]) of
                host_throttle ->
                    ok;
                Error ->
                    {error, Error}
            end;
        _InfoList ->
            ok
    end;
create(lookup_table) ->
    case ets:info(lookup_table) of
        undefined ->
            case ets:new(lookup_table, [public, named_table, bag]) of
                lookup_table ->
                    ok;
                Error ->
                    {error, Error}
            end;
        _InfoList ->
            ok
    end;
create(handler_registry) ->
    case ets:info(handler_registry) of
        undefined ->
            case ets:new(handler_registry, [set, public, named_table]) of
                handler_registry ->
                    ok;
                Error ->
                    {error, Error}
            end;
        _InfoList ->
            ok
    end.

%% @doc Insert value in ets table.
-spec insert(atom(), tuple()) -> ok | {error, Reason :: term()}.
insert(Table, Value)->
    case ets:insert(Table, Value) of
        true ->
            ok;
        Error ->
            {error, Error}
    end.

%% @doc Delete entire ets table.
-spec delete_table(atom()) -> ok | {error, Reason :: term()}.
delete_table(Table)->
    case ets:delete(Table) of
        true ->
            ok;
        Error ->
            {error, Error}
    end.

%% @doc Delete an entry in the ets table.Ets always returns true for this function.
-spec delete(atom(), term()) -> ok.
delete(Table, Key) ->
    ets:delete(Table, Key),
    ok.

%% @doc Backup a specific ets table.
%% @see https://github.com/SiftLogic/erl-dns/issues/3
-spec backup_table(atom()) -> ok | {error, Reason :: term()}.
backup_table(_Table)->
    {error, not_implemented}.

%% @doc Should backup all ets tables.
%% @see https://github.com/SiftLogic/erl-dns/issues/3
-spec backup_tables() -> ok | {error, Reason :: term()}.
backup_tables() ->
    {error, not_implemented}.

%% @doc Select from ets using key, value.
-spec select(atom(), term()) -> tuple().
select(Table, Key) ->
    ets:lookup(Table, Key).

%% @doc Select from ets using match specs.
-spec select(atom(), list(), integer()) -> tuple() | '$end_of_table'.
select(Table, MatchSpec, Limit) ->
    ets:select(Table, MatchSpec, Limit).

%% @doc Wrapper for foldl in ets.
-spec foldl(fun(), list(), atom())  -> Acc :: term() | {error, Reason :: term()}.
foldl(Fun, Acc, Table) ->
    ets:foldl(Fun, Acc, Table).

%% @doc Empty ets table. Ets always returns true for this function.
-spec empty_table(atom()) -> ok.
empty_table(Table) ->
    ets:delete_all_objects(Table),
    ok.

%% @doc Lists the ets table
-spec list_table(atom()) -> term() | {error, term()}.
list_table(TableName) ->
    try ets:tab2list(TableName)
    catch
        error:R ->
            {error, R}
    end.