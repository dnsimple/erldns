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

-module(erldns_storage).

-behaviour(gen_server).

%% inter-module API
-export([start_link/0]).

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
         list_table/1,
         load_zones/0,
         load_zones/1]).

%% gen_server callbacks
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).


-record(state, {}).

-define(POLL_WAIT_HOURS, 1).
-define(FILENAME, "zones.json").

%% Gen Server Callbacks
start_link() ->
  gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%% @doc Inits the module, and sends a "timeout" to handle_info to start the poller for table backup
init([]) ->
  %%This call to handle_info starts the timer to backup tables in the given interval.
  {ok, #state{}, 0}.

handle_call(_Request, _From, State) ->
  {reply, ok, State, 0}.

handle_cast(_Msg, State) ->
  {noreply, State, 0}.

%% @doc Backups the tables in the given period
handle_info(timeout, State) ->
  Before = erlang:timestamp(),
  {error, not_implemented} = backup_tables(),
  TimeSpentMs = timer:now_diff(erlang:timestamp(), Before) div 1000,
  {noreply, State, max((?POLL_WAIT_HOURS * 60000) - TimeSpentMs, 0)};
handle_info(_Info, State) ->
  {noreply, State, 0}.

terminate(_Reason, _State) ->
  ok.

code_change(_OldVsn, State, _Extra) ->
  {ok, State}.


%% Public API
%% @doc API for a module's function calls. Please note that all crashes should be handled at the
%% lowest level of the API (ex. erldns_storage_json).
%% @end

%% @doc Call to a module's create. Creates a new table.
-spec create(atom()) -> ok | {error, Reason :: term()}.
create(Table) ->
  Module = mod(Table),
  Module:create(Table).

%% @doc Call to a module's insert. Inserts a value into the table.
-spec insert(atom(), tuple()) -> ok | {error, Reason :: term()}.
insert(Table, Value)->
  Module = mod(Table),
  Module:insert(Table, Value).

%% @doc Call to a module's delete_table. Deletes the entire table.
-spec delete_table(atom()) -> ok | {error, Reason :: term()}.
delete_table(Table)->
  Module = mod(Table),
  Module:delete_table(Table).

%% @doc Call to a module's delete. Deletes a key value from a table.
-spec delete(atom(), term()) -> ok | {error, Reason :: term()}.
delete(Table, Key) ->
  Module = mod(Table),
  Module:delete(Table, Key).

-spec select_delete(atom(), list()) -> {ok, Count :: integer()} | {error, Reason :: term()}.
select_delete(Table, MatchSpec) ->
  Module = mod(Table),
  Module:select_delete(Table, MatchSpec).

%% @doc Backup the table to the JSON file.
%% @see https://github.com/SiftLogic/erl-dns/issues/3
-spec backup_table(atom()) -> ok | {error, Reason :: term()}.
backup_table(Table)->
  Module = mod(Table),
  Module:backup_table(Table).

%% @doc Backup the tables to the JSON file.
%% @see https://github.com/SiftLogic/erl-dns/issues/3
-spec backup_tables() -> ok | {error, Reason :: term()}.
backup_tables() ->
  Module = mod(),
  Module:backup_tables().

%% @doc Call to a module's select. Uses table key pair, and can be considered a "lookup" in terms of ets.
-spec select(atom(), term()) -> [tuple()].
select(Table, Key) ->
  Module = mod(Table),
  Module:select(Table, Key).

%% @doc Call to a module's select. Uses a matchspec to generate matches.
-spec select(atom(), list(), infinite | integer()) -> [tuple()].
select(Table, MatchSpec, Limit) ->
  Module = mod(Table),
  Module:select(Table, MatchSpec, Limit).

%% @doc Call to a module's foldl.
-spec foldl(fun(), list(), atom())  -> Acc :: term() | {error, Reason :: term()}.
foldl(Fun, Acc, Table) ->
  Module = mod(Table),
  Module:foldl(Fun, Acc, Table).

%% @doc This function emptys the specified table of all values.
-spec empty_table(atom()) -> ok | {error, Reason :: term()}.
empty_table(Table) ->
  Module = mod(Table),
  Module:empty_table(Table).

%% @doc List all elements in a table.
-spec list_table(atom()) -> [] | term() | {error, term()}.
list_table(TableName) ->
  Module = mod(TableName),
  Module:list_table(TableName).

%% @doc Load zones from a file. The default file name is "zones.json".(copied from erldns_zone_loader.erl)
-spec load_zones() -> {ok, integer()} | {err,  atom()}.
load_zones() ->
  load_zones(filename()).

%% @doc Load zones from a file. The default file name is "zones.json".(copied from erldns_zone_loader.erl)
-spec load_zones(list()) -> {ok, integer()} | {err,  atom()}.
load_zones(Filename) when is_list(Filename) ->
  case file:read_file(Filename) of
    {ok, Binary} ->
      lager:debug("Parsing zones JSON"),
      JsonZones = jsx:decode(Binary),
      lager:debug("Putting zones into cache"),
      lists:foreach(
        fun(JsonZone) ->
            Zone = erldns_zone_parser:zone_to_erlang(JsonZone),
            ok = erldns_zone_cache:put_zone(Zone)
        end, JsonZones),
      lager:debug("Loaded zones (count: ~p)", [length(JsonZones)]),
      {ok, length(JsonZones)};
    {error, Reason} ->
      lager:error("Failed to load zones (reason: ~p)", [Reason]),
      {err, Reason}
  end.

%% Internal API
%% @doc Get file name from env, or return default (copied from erldns_zone_loader.erl)
filename() ->
  case application:get_env(erldns, zones) of
    {ok, Filename} -> Filename;
    _ -> ?FILENAME
  end.

%% @doc This function retrieves the module name to be used for a given application or table
%% (ex. erldns_storage_json...). Matched tables are always going to use ets because they are either
%% cached, or functionality is optimal in ets.
%% @end
mod() ->
  erldns_config:storage_type().

mod(packet_cache) ->
  erldns_storage_json;
mod(host_throttle) ->
  erldns_storage_json;
mod(handler_registry) ->
  erldns_storage_json;
mod(geolocation) ->
  erldns_storage_mnesia;
mod(lookup_table) ->
  erldns_storage_json;
mod(_Table) ->
  erldns_config:storage_type().
