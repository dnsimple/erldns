%% Copyright (c) 2012-2014, Aetrion LLC
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

%% @doc A cache holding all of the zone data.
%%
%% Write operations occur through the cache process mailbox, whereas read
%% operations may occur either through the mailbox or directly through the
%% underlying data store, depending on performance requirements.
-module(erldns_zone_cache).

-behavior(gen_server).

-include_lib("dns/include/dns.hrl").
-include("erldns.hrl").

-export([start_link/0]).

% Read APIs
-export([
         find_zone/1,
         find_zone/2,
         get_zone/1,
         get_zone_with_records/1,
         get_authority/1,
         get_delegations/1,
         get_records_by_name/1,
         in_zone/1,
         zone_names_and_versions/0
        ]).

% Write APIs
-export([
         put_zone/1,
         put_zone/2,
         put_zone_async/1,
         put_zone_async/2,
         delete_zone/1
        ]).

% Gen server hooks
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3
        ]).

-define(SERVER, ?MODULE).

-record(state, {parsers, tref = none}).

%% @doc Start the zone cache process.
-spec start_link() -> any().
start_link() ->
  gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

% ----------------------------------------------------------------------------------------------------
% Read API

%% @doc Find a zone for a given qname.
-spec find_zone(dns:dname()) -> {ok, #zone{}} | {error, zone_not_found} | {error, not_authoritative}.
find_zone(Qname) ->
  find_zone(normalize_name(Qname), get_authority(Qname)).

%% @doc Find a zone for a given qname.
-spec find_zone(dns:dname(), {error, any()} | {ok, dns:rr()} | [dns:rr()] | dns:rr()) ->
  {ok, #zone{}} | {error, zone_not_found} | {error, not_authoritative}.
find_zone(Qname, {error, _}) ->
  find_zone(Qname, []);
find_zone(Qname, {ok, Authority}) ->
  find_zone(Qname, Authority);
find_zone(_Qname, []) ->
  {error, not_authoritative};
find_zone(Qname, Authorities) when is_list(Authorities) ->
  find_zone(Qname, lists:last(Authorities));
find_zone(Qname, Authority) when is_record(Authority, dns_rr) ->
  Name = normalize_name(Qname),
  case dns:dname_to_labels(Name) of
    [] -> {error, zone_not_found};
    [_] -> {error, zone_not_found};
    [_|Labels] ->
      case get_zone(Name) of
        {ok, Zone} -> Zone;
        {error, zone_not_found} ->
          case Name =:= Authority#dns_rr.name of
            true -> {error, zone_not_found};
            false -> find_zone(dns:labels_to_dname(Labels), Authority)
          end
      end
  end.

%% @doc Get a zone for the specific name. This function will not attempt to resolve
%% the dname in any way, it will simply look up the name in the underlying data store.
-spec get_zone(dns:dname()) -> {ok, #zone{}} | {error, zone_not_found}.
get_zone(Name) ->
  NormalizedName = normalize_name(Name),
  case erldns_storage:select(zones, NormalizedName) of
    [{NormalizedName, Zone}] ->
        {ok, Zone#zone{name = NormalizedName, records = [], records_by_name=trimmed}};
    _Res ->
        {error, zone_not_found}
  end.

%% @doc Get a zone for the specific name, including the records for the zone.
-spec get_zone_with_records(dns:dname()) -> {ok, #zone{}} | {error, zone_not_found}.
get_zone_with_records(Name) ->
  NormalizedName = normalize_name(Name),
  case erldns_storage:select(zones, NormalizedName) of
    [{NormalizedName, Zone}] -> {ok, Zone};
    _ -> {error, zone_not_found}
  end.

%% @doc Find the SOA record for the given DNS question.
-spec get_authority(dns:message() | dns:dname()) -> {error, no_question} | {error, no_authority} | {ok, dns:rr()}.
get_authority(Message) when is_record(Message, dns_message) ->
  case Message#dns_message.questions of
    [] -> {error, no_question};
    Questions -> 
      Question = lists:last(Questions),
      get_authority(Question#dns_query.name)
  end;
get_authority(Name) ->
  case find_zone_in_cache(normalize_name(Name)) of
    {ok, Zone} -> {ok, Zone#zone.authority};
    _ -> {error, authority_not_found}
  end.

%% @doc Get the list of NS and glue records for the given name. This function
%% will always return a list, even if it is empty.
-spec get_delegations(dns:dname()) -> [dns:rr()] | [].
get_delegations(Name) ->
  case find_zone_in_cache(Name) of
    {ok, Zone} ->
      lists:filter(fun(R) -> apply(erldns_records:match_type(?DNS_TYPE_NS), [R]) and apply(erldns_records:match_glue(Name), [R]) end, Zone#zone.records);
    _ ->
      []
  end.

%% @doc Return the record set for the given dname.
-spec get_records_by_name(dns:dname()) -> [dns:rr()].
get_records_by_name(Name) ->
  case find_zone_in_cache(Name) of
    {ok, Zone} ->
      case dict:find(normalize_name(Name), Zone#zone.records_by_name) of
        {ok, RecordSet} -> RecordSet;
        _ -> []
      end;
    _ ->
      []
  end.

%% @doc Check if the name is in a zone.
-spec in_zone(binary()) -> boolean().
in_zone(Name) ->
  case find_zone_in_cache(Name) of
    {ok, Zone} ->
      is_name_in_zone(Name, Zone);
    _ ->
      false
  end.

%% @doc Return a list of tuples with each tuple as a name and the version SHA
%% for the zone.
-spec zone_names_and_versions() -> [{dns:dname(), binary()}].
zone_names_and_versions() ->
  erldns_storage:foldl(fun(#zone{name = Name, version = Version}, NamesAndShas) ->
                         [{Name, Version} | NamesAndShas]
                       end, [], zones).

% ----------------------------------------------------------------------------------------------------
% Write API

%% @doc Put a name and its records into the cache, along with a SHA which can be
%% used to determine if the zone requires updating.
%%
%% This function will build the necessary Zone record before interting.
-spec put_zone({binary(), binary(), [#dns_rr{}]}) -> ok.
put_zone({Name, Sha, Records}) ->
  erldns_storage:insert(zones, {normalize_name(Name), build_zone(Name, Sha, Records)}),
  ok.

%% @doc Put a zone into the cache and wait for a response.
-spec put_zone(binary(), #zone{}) -> ok.
put_zone(Name, #zone{} = Zone) ->
  erldns_storage:insert(zones, {normalize_name(Name), Zone}),
  ok.

%% @doc Put a zone into the cache without waiting for a response.
-spec put_zone_async({binary(), binary(), [#dns_rr{}]}) -> ok.
put_zone_async({Name, Sha, Records}) ->
  erldns_storage:insert(zones, {normalize_name(Name), build_zone(Name, Sha, Records)}),
  ok.

%% @doc Put a zone into the cache without waiting for a response.
-spec put_zone_async(binary(), #zone{}) -> ok.
put_zone_async(Name, Zone) ->
  erldns_storage:insert(zones, {normalize_name(Name), Zone}),
  ok.

%% @doc Remove a zone from the cache without waiting for a response.
-spec delete_zone(binary()) -> any().
delete_zone(Name) ->
  gen_server:cast(?SERVER, {delete, Name}).



% ----------------------------------------------------------------------------------------------------
% Gen server init

%% @doc Initialize the zone cache.
-spec init([]) -> {ok, #state{}}.
init([]) ->
  case erldns_config:storage_type() of
    erldns_storage_mnesia ->
        erldns_storage:create(schema);
    _ ->
        ok
  end,
  erldns_storage:create(zones),
  erldns_storage:create(authorities),
  {ok, #state{parsers = []}}.

% ----------------------------------------------------------------------------------------------------
% gen_server callbacks

%% @doc Write the zone into the cache.
handle_call({put, Name, Zone}, _From, State) ->
  erldns_storage:insert(zones, {normalize_name(Name), Zone}),
  {reply, ok, State};

handle_call({put, Name, Sha, Records}, _From, State) ->
  erldns_storage:insert(zones, {normalize_name(Name), build_zone(Name, Sha, Records)}),
  {reply, ok, State}.

handle_cast({put, Name, Zone}, State) ->
  erldns_storage:insert(zones, {normalize_name(Name), Zone}),
  {noreply, State};

handle_cast({put, Name, Sha, Records}, State) ->
  erldns_storage:insert(zones, {normalize_name(Name), build_zone(Name, Sha, Records)}),
  {noreply, State};

handle_cast({delete, Name}, State) ->
  erldns_storage:delete(zones, normalize_name(Name)),
  {noreply, State};

handle_cast(Message, State) ->
  lager:debug("Received unsupported message: ~p", [Message]),
  {noreply, State}.

handle_info(_Message, State) ->
  {noreply, State}.

terminate(_Reason, _State) ->
  ok.

code_change(_PreviousVersion, State, _Extra) ->
  {ok, State}.


% Internal API
is_name_in_zone(Name, Zone) ->
  case dict:is_key(normalize_name(Name), Zone#zone.records_by_name) of
    true -> true;
    false ->
      case dns:dname_to_labels(Name) of
        [] -> false;
        [_] -> false;
        [_|Labels] -> is_name_in_zone(dns:labels_to_dname(Labels), Zone)
      end
  end.

find_zone_in_cache(Qname) ->
  Name = normalize_name(Qname),
  case dns:dname_to_labels(Name) of
    [] -> {error, zone_not_found};
    [_] -> {error, zone_not_found};
    [_|Labels] ->
      case erldns_storage:select(zones, Name) of
        [{Name, Zone}] -> {ok, Zone};
        _ -> find_zone_in_cache(dns:labels_to_dname(Labels))
      end
  end.

build_zone(Qname, Version, Records) ->
  RecordsByName = build_named_index(Records),
  Authorities = lists:filter(erldns_records:match_type(?DNS_TYPE_SOA), Records),
  #zone{name = Qname, version = Version, record_count = length(Records), authority = Authorities, records = Records, records_by_name = RecordsByName}.

build_named_index(Records) -> build_named_index(Records, dict:new()).
build_named_index([], Idx) -> Idx;
build_named_index([R|Rest], Idx) ->
  case dict:find(R#dns_rr.name, Idx) of
    {ok, Records} ->
      build_named_index(Rest, dict:store(normalize_name(R#dns_rr.name), Records ++ [R], Idx));
    error ->
      build_named_index(Rest, dict:store(normalize_name(R#dns_rr.name), [R], Idx))
  end.

normalize_name(Name) when is_list(Name) -> string:to_lower(Name);
normalize_name(Name) when is_binary(Name) -> list_to_binary(string:to_lower(binary_to_list(Name))).
