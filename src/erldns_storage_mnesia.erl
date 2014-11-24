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
create(schema) ->
    case application:stop(mnesia) of
        ok ->
            ok;
        {error, Reason} ->
            lager:warning("Could not stop mnesia for reason ~p~n", [Reason])
    end,
    filelib:ensure_dir("db/zone.DCD"),
    application:set_env(mnesia, dir, "db"),
    case mnesia:create_schema([node()]) of
        {error, {_, {already_exists, _}}} ->
            lager:warning("The schema already exists on node ~p.~n", [node()]),
            ok;
        ok ->
            ok
    end,
    application:start(mnesia);
create(zones) ->
    ok = ensure_mnesia_started(),
    case mnesia:create_table(zones,
        [{attributes, record_info(fields, zone)},
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

-spec insert(atom(), #zone{}) -> ok.
insert(zones, {_N, #zone{name = Name,
                         version = Version,
                         authority = Authority,
                         record_count = RecordCount,
                         records = Records,
                         records_by_name = RecordsByName,
                         records_by_type = RecordsByType
}})->
    Write = fun() ->mnesia:write(#zone{name = Name,
                                       version = Version,
                                       authority = Authority,
                                       record_count = RecordCount,
                                       records = Records,
                                       records_by_name = RecordsByName,
                                       records_by_type = RecordsByType
    }) end,
    mnesia:activity(transaction, Write).


-spec delete_table(atom()) -> true.
delete_table(Table) ->
    DeleteTable = fun() -> mnesia:delete_table(Table) end,
    mnesia:activity(transaction, DeleteTable).

-spec delete(Table :: atom(), Key :: term()) -> true.
delete(Table, Key)->
   Delete = fun() -> mnesia:delete({Table, Key})end,
   mnesia:activity(transaction, Delete).

-spec backup_table(atom()) -> ok | {error, Reason :: term()}.
backup_table(_Table)->
    Backup = fun() -> mnesia:backup(mnesia:schema()) end,
    mnesia:activity(transaction, Backup).


-spec backup_tables() -> ok | {error, Reason :: term()}.
backup_tables()->
    ok.

-spec select(Table :: atom(), Key :: term()) -> tuple().
select(Table, Key)->
    Select = fun () -> mnesia:read({Table, Key}) end,
    mnesia:activity(transaction, Select).

-spec select(atom(), list(), integer()) -> tuple() | '$end_of_table'.
select(_Table, MatchSpec, _Limit) ->
    MatchObject = fun() -> mnesia:match_object(MatchSpec) end,
    mnesia:activity(transaction, MatchObject).

-spec foldl(fun(), list(), atom())  -> Acc :: term() | {error, Reason :: term()}.
foldl(Fun, Acc, Table) ->
    Foldl = fun() -> mnesia:foldl(Fun, Acc, Table) end,
    mnesia:activity(transaction, Foldl).

-spec empty_table(atom()) -> ok.
empty_table(Table) ->
    ClearTable = fun() ->mnesia:clear_table(Table) end,
    mnesia:activity(transaction, ClearTable).

%% Private
ensure_mnesia_started() ->
    case application:start(mnesia) of
        ok ->
            ok;
        {error,{already_started, mnesia}} ->
            ok;
        {error, Reason} ->
            {error, Reason}
    end.