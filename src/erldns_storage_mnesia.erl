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

-module(erldns_storage_mnesia).

-include("erldns.hrl").

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
%% @doc Create the schema for mnesia, get the configuration from the config. Function sends 'ok'
%% if schema is created, or if it already exists.
%% @end
create(schema) ->
    ok = ensure_mnesia_started(),
    case erldns_config:storage_dir() of
        undefined ->
            lager:error("You need to add a directory for mnesia in erldns.config"),
            exit(-1);
        Dir ->
            filelib:ensure_dir(Dir)
    end,
    case application:stop(mnesia) of
        ok ->
            ok;
        {error, Reason} ->
            lager:warning("Could not stop mnesia for reason ~p~n", [Reason])
    end,
    case mnesia:create_schema([node()]) of
        {error, {_, {already_exists, _}}} ->
            lager:warning("The schema already exists on node ~p.~n", [node()]),
            ok;
        ok ->
            ok
    end,
    application:start(mnesia);
%% @doc Match the table names for every create. This enables different records to be used and
%% attributes to be sent to the tables.
%% @end

%% @doc Zones table has a discrepancy between record name, and table name. Be sure to use necesssary
%% functions for this difference.
%% @end
create(zones) ->
    ok = ensure_mnesia_started(),
    case mnesia:create_table(zones,
        [{attributes, record_info(fields, zone)},
            {record_name, zone},
            {disc_copies, [node()]}]) of
        {aborted, {already_exists, zones}} ->
            lager:warning("The zone table already exists on node ~p.~n",
                [node()]),
            ok;
        {atomic, ok} ->
            ok
    end;
create(authorities) ->
    ok = ensure_mnesia_started(),
    case mnesia:create_table(authorities,
        [{attributes, record_info(fields, authorities)},
            {disc_copies, [node()]}]) of
        {aborted, {already_exists, authorities}} ->
            lager:warning("The zone table already exists on node ~p.~n",
                [node()]),
            ok;
        {atomic, ok} ->
            ok
    end.

%% @doc Insert into specified table. zone_cache calls this by {name, #zone{}}
insert(zones, #zone{} = Zone)->
    Write = fun() -> mnesia:write(zones, Zone, write) end,
    ok = mnesia:activity(transaction, Write),
    ok;
insert(zones, {_N, #zone{} = Zone})->
    Write = fun() -> mnesia:write(zones, Zone, write) end,
    ok = mnesia:activity(transaction, Write),
    ok;
insert(authorities, #authorities{} = Auth) ->
    Write = fun() -> mnesia:write(authorities, Auth, write) end,
    ok = mnesia:activity(transaction, Write),
    ok.

%% @doc delete the entire table.
-spec delete_table(atom()) -> true | {aborted, any()}.
delete_table(Table) ->
    {atomic, ok} = mnesia:delete_table(Table),
    ok.

%% @doc Delete a mnesia record, have to do things different for zones since we specified {record_name, zone}
%% in the table creation.
-spec delete(Table :: atom(), Key :: term()) -> true | any().
delete(zones, Key)->
    ok = mnesia:dirty_delete({zones, Key}),
    ok;
delete(Table, Key)->
   Delete = fun() -> mnesia:delete({Table, Key}) end,
    ok = mnesia:activity(transaction, Delete),
    ok.

%% @doc Should backup the tables in the schema.
%% @see https://github.com/SiftLogic/erl-dns/issues/3
-spec backup_table(atom()) -> ok | {error, Reason :: term()}.
backup_table(_Table)->
    Backup = fun() -> mnesia:backup(mnesia:schema()) end,
    ok = mnesia:activity(transaction, Backup),
    ok.

%% @see https://github.com/SiftLogic/erl-dns/issues/3
-spec backup_tables() -> ok | {error, Reason :: term()}.
backup_tables()->
    ok.

%% @doc Select based on key value.
-spec select(Table :: atom(), Key :: term()) -> tuple().
select(Table, Key)->
    Select = fun () ->
                case mnesia:read({Table, Key}) of
                    [Record] -> [{Key,Record}];
                    _ -> []
                end
            end,
    mnesia:activity(transaction, Select).

%% @doc Select using a match spec.
-spec select(atom(), list(), integer()) -> tuple() | '$end_of_table'.
select(_Table, MatchSpec, _Limit) ->
    MatchObject = fun() -> mnesia:match_object(MatchSpec) end,
    mnesia:activity(transaction, MatchObject).

%% @doc Wrapper for foldl.
-spec foldl(fun(), list(), atom())  -> Acc :: term() | {error, Reason :: term()}.
foldl(Iterator, _Acc, Table) ->
    Exec = fun() -> mnesia:foldl(Iterator, [], Table) end,
    case mnesia:is_transaction() of
    true ->
        Exec();
    false ->
        mnesia:activity(transaction, Exec)
    end.

%% @doc Clear all objects from given table in mnesia DB.
-spec empty_table(atom()) -> ok | {aborted, term()}.
empty_table(Table) ->
    {atomic, ok} = mnesia:clear_table(Table),
    ok.

%% Private
%% @doc Checks if mnesia is started, if not if starts mnesia.
-spec ensure_mnesia_started() -> ok | {error, any()}.
ensure_mnesia_started() ->
    case application:start(mnesia) of
        ok ->
            ok;
        {error,{already_started, mnesia}} ->
            ok;
        {error, Reason} ->
            {error, Reason}
    end.