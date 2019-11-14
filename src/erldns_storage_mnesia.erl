%% Copyright (c) 2015, SiftLogic LLC
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

%% The function takes advantage of mnesia record matches

-dialyzer({nowarn_function, list_table/1}).

-include("erldns.hrl").

%% API
-export([create/1,
         insert/2,
         delete_table/1,
         delete/2,
         select_delete/2,
         backup_table/1,
         backup_tables/0,
         select/2,
         select/3,
         foldl/3,
         empty_table/1,
         list_table/1]).

-spec create(atom()) -> ok.
%% @doc Create the schema for mnesia, get the configuration from the config. Function sends 'ok'
%% if schema is created, or if it already exists.
%% @end
create(schema) ->
  ok = ensure_mnesia_started(),
  case erldns_config:storage_dir() of
    undefined ->
      lager:error("You need to add a directory for mnesia in erldns.config");
    Dir ->
      ok = filelib:ensure_dir(Dir),
      ok = application:set_env(mnesia, dir, Dir)
  end,
  case application:stop(mnesia) of
    ok ->
      ok;
    {error, Reason} ->
      lager:warning("Could not stop mnesia (reason: ~p)", [Reason])
  end,
  case mnesia:create_schema([node()]) of
    {error, {_, {already_exists, _}}} ->
      lager:warning("The schema already exists (node: ~p)", [node()]),
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
      lager:warning("The zone table already exists (node: ~p)", [node()]),
      ok;
    {atomic, ok} ->
      ok;
    Error ->
      {error, Error}
  end;
create(zone_records) ->
  case mnesia:create_table(zone_records,
                           [{attributes, record_info(fields, zone_records)},
                            {disc_copies, [node()]}]) of
    {aborted, {already_exists, zone_records}} ->
      lager:warning("The zone records table already exists (node: ~p)", [node()]),
      ok;
    {atomic, ok} ->
      ok;
    Error ->
      {error, Error}
  end;
create(zone_records_typed) ->
  case mnesia:create_table(zone_records_typed,
                           [{attributes, record_info(fields, zone_records_typed)},
                            {disc_copies, [node()]}]) of
    {aborted, {already_exists, zone_records_typed}} ->
      lager:warning("The zone records table already exists (node: ~p)", [node()]),
      ok;
    {atomic, ok} ->
      ok;
    Error ->
      {error, Error}
  end;
create(authorities) ->
  ok = ensure_mnesia_started(),
  case mnesia:create_table(authorities,
                           [{attributes, record_info(fields, authorities)},
                            {disc_copies, [node()]}]) of
    {aborted, {already_exists, authorities}} ->
      lager:warning("The authority table already exists (node: ~p)", [node()]),
      ok;
    {atomic, ok} ->
      ok;
    Error ->
      {error, Error}
  end.

%% @doc Insert into specified table. zone_cache calls this by {name, #zone{}}
-spec insert(atom(), any()) -> any().
insert(zones, #zone{} = Zone)->
  Write = fun() -> mnesia:write(zones, Zone, write) end,
  case mnesia:activity(transaction, Write) of
    ok ->
      ok;
    Error ->
      {error, Error}
  end;
insert(zones, {_N, #zone{} = Zone})->
  Write = fun() -> mnesia:write(zones, Zone, write) end,
  case mnesia:activity(transaction, Write) of
    ok ->
      ok;
    Error ->
      {error, Error}
  end;
insert(zone_records, {{ZoneName, Fqdn}, Records}) ->
  Write = fun() -> mnesia:write(zone_records, #zone_records{zone_name = ZoneName, fqdn = Fqdn, records = Records}, write) end,
  case mnesia:activity(transaction, Write) of
    ok ->
      ok;
    Error ->
      {error, Error}
  end;
insert(zone_records_typed, {{ZoneName, Fqdn, Type}, Records}) ->
  Write = fun() -> mnesia:write(zone_records_typed, #zone_records_typed{zone_name = ZoneName, fqdn = Fqdn, records = Records, type = Type}, write) end,
  case mnesia:activity(transaction, Write) of
    ok ->
      ok;
    Error ->
      {error, Error}
  end;
insert(authorities, #authorities{} = Auth) ->
  Write = fun() -> mnesia:write(authorities, Auth, write) end,
  case mnesia:activity(transaction, Write) of
    ok ->
      ok;
    Error ->
      {error, Error}
  end.

%% @doc delete the entire table.
-spec delete_table(atom()) -> ok | {aborted, any()}.
delete_table(Table) ->
  case mnesia:delete_table(Table) of
    {atomic, ok} ->
      ok;
    {aborted, Reason} ->
      {error, Reason}
  end.

%% @doc Delete a mnesia record, have to do things different for zones since we specified {record_name, zone}
%% in the table creation.
-spec delete(Table :: atom(), Key :: term()) -> ok | any().
delete(zones, Key)->
  mnesia:dirty_delete({zones, Key});
delete(Table, Key)->
  case mnesia:is_transaction() of
    true ->
      Delete = fun() -> mnesia:delete({Table, Key}) end,
      mnesia:activity(transaction, Delete);
    false ->
      mnesia:dirty_delete({Table, Key})
  end.

%% @doc Delete all zone records or zone records typed based on the match spec. The match spec
%% is given as an ETS match spec, thus it needs to be converted to a record match spec for
%% Mnesia.
-spec select_delete(atom(), list()) -> {ok, Count :: integer()} | {error, Reason :: term()}.
select_delete(Table, [{{{ZoneName, Fqdn}, _}, _, _}])->
  SelectDelete = fun() ->
                     Records =  mnesia:match_object(Table, {zone_records, ZoneName, Fqdn, '_'}, write),
                     lists:foreach(fun(R) -> mnesia:dirty_delete_object(R) end, Records),
                     {ok, length(Records)}
                 end,
  mnesia:activity(transaction, SelectDelete);
select_delete(Table, [{{{ZoneName, Fqdn, Type}, _}, _, _}])->
  SelectDelete = fun() ->
                     Records = mnesia:match_object(Table, {zone_records_typed, ZoneName, Fqdn, Type, '_'}, write),
                     lists:foreach(fun(R) -> mnesia:dirty_delete_object(R) end, Records),
                     {ok, length(Records)}
                 end,
  mnesia:activity(transaction, SelectDelete).

%%
%% @doc Should backup the tables in the schema.
%% @see https://github.com/SiftLogic/erl-dns/issues/3
-spec backup_table(atom()) -> ok | {error, Reason :: term()}.
backup_table(_Table)->
  Backup = fun() -> mnesia:backup(mnesia:schema()) end,
  mnesia:activity(transaction, Backup).

%% @see https://github.com/SiftLogic/erl-dns/issues/3
-spec backup_tables() -> ok | {error, Reason :: term()}.
backup_tables()->
  {error, not_implemented}.

%% @doc Select based on key value.
-spec select(Table :: atom(), Key :: term()) -> [tuple()].
select(Table, Key)->
  Select = fun () ->
               case mnesia:read({Table, Key}) of
                 [Record] -> [{Key,Record}];
                 _ -> []
               end
           end,
  mnesia:activity(transaction, Select).

%% @doc Select using a match spec.
-spec select(atom(), list(), infinite | integer()) -> [tuple()].
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
  case mnesia:clear_table(Table) of
    {atomic, ok} ->
      ok;
    {aborted, Reason} ->
      {error, Reason}
  end.

%% @doc Lists the contents of the given table.
-spec list_table(atom()) ->
  [] | [#zone{}] | [#authorities{}] | [tuple()] | {error, doesnt_exist}.
list_table(zones) ->
  Pattern = #zone{name ='_', version = '_', authority = '_', record_count = '_',
                  records = '_', records_by_name = '_', records_by_type = '_'},
  mnesia:dirty_match_object(zones, Pattern);
list_table(authorities) ->
  Pattern = #authorities{owner_name = '_', ttl = '_', class = '_', name_server = '_', email_addr = '_',
                         serial_num = '_', refresh = '_', retry = '_', expiry = '_', nxdomain = '_'},
  select(authorities, Pattern, 0);
list_table(_Name) ->
  {error, doesnt_exist}.

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
