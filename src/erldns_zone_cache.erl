%% Copyright (c) 2012-2013, Aetrion LLC
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
-export(
  [
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
-export([put_zone/1,
    put_zone/2,
    put_zone_async/1,
    put_zone_async/2,
    delete_zone/1]).

% Gen server hooks
-export([init/1,
	 handle_call/3,
	 handle_cast/2,
	 handle_info/2,
	 terminate/2,
	 code_change/3
       ]).

-define(SERVER, ?MODULE).

-record(state, {parsers}).

%% @doc Start the zone cache process.
-spec start_link() -> any().
start_link() ->
  gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

% ----------------------------------------------------------------------------------------------------
% Read API

%% @doc Find a zone for a given qname.
-spec find_zone(dns:dname()) -> {ok, #zone{}} | {error, zone_not_found} | {error, not_authoritative}.
find_zone(Qname) ->
  find_zone(normalize_name(Qname), get_authority(Qname)). %% Results in a message in the erldns_zone_cache process mailbox

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
      case get_zone(Name) of %% Results in a message in the erldns_zone_cache process mailbox
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
  gen_server:call(?SERVER, {get, Name}).

%% @doc Get a zone for the specific name, including the records for the zone.
-spec get_zone_with_records(dns:dname()) -> {ok, #zone{}} | {error, zone_not_found}.
get_zone_with_records(Name) ->
  gen_server:call(?SERVER, {get_zone_with_records, Name}).

%% @doc Find the SOA record for the given DNS question.
-spec get_authority(dns:message()) -> {error, no_question} | {error, no_authority} | {ok, dns:rr()}.
get_authority(Message) when is_record(Message, dns_message) ->
  case Message#dns_message.questions of
    [] -> {error, no_question};
    Questions -> 
      Question = lists:last(Questions),
      get_authority(Question#dns_query.name)
  end;
get_authority(Name) ->
  gen_server:call(?SERVER, {get_authority, Name}).

%% @doc Get the list of NS and glue records for the given name. This function
%% will always return a list, even if it is empty.
-spec get_delegations(dns:dname()) -> {ok, [dns:rr()]} | [].
get_delegations(Name) ->
  Result = gen_server:call(?SERVER, {get_delegations, Name}),
  case Result of
    {ok, Delegations} -> Delegations;
    _ -> []
  end.

get_records_by_name(Name) ->
  gen_server:call(?SERVER, {get_records_by_name, Name}).

%% @doc Check if the name is in a zone.
-spec in_zone(binary()) -> boolean().
in_zone(Name) ->
  gen_server:call(?SERVER, {in_zone, Name}).

%% @doc Return a list of tuples with each tuple as a name and the version SHA
%% for the zone.
-spec zone_names_and_versions() -> [{dns:dname(), binary()}].
zone_names_and_versions() ->
  gen_server:call(?SERVER, {zone_names_and_versions}).

% ----------------------------------------------------------------------------------------------------
% Write API

%% @doc Put a name and its records into the cache, along with a SHA which can be
%% used to determine if the zone requires updating.
%%
%% This function will build the necessary Zone record before interting.
-spec put_zone({binary(), binary(), [#dns_rr{}]}) -> #zone{}.
put_zone({Name, Sha, Records}) ->
  Zone = build_zone(Name, Sha, Records),
  gen_server:call(?SERVER, {put, Name, Zone}),
  Zone.

%% @doc Put a zone into the cache and wait for a response.
-spec put_zone(binary(), #zone{}) -> #zone{}.
put_zone(Name, Zone) ->
  gen_server:call(?SERVER, {put, Name, Zone}),
  Zone.

%% @doc Put a zone into the cache without waiting for a response.
-spec put_zone_async({binary(), binary(), [#dns_rr{}]}) -> #zone{}.
put_zone_async({Name, Sha, Records}) ->
  Zone = build_zone(Name, Sha, Records),
  gen_server:cast(?SERVER, {put, Name, Zone}),
  Zone.

%% @doc Put a zone into the cache without waiting for a response.
-spec put_zone_async(binary(), #zone{}) -> #zone{}.
put_zone_async(Name, Zone) ->
  gen_server:cast(?SERVER, {put, Name, Zone}),
  Zone.

%% @doc Remove a zone from the cache without waiting for a response.
-spec delete_zone(binary()) -> any().
delete_zone(Name) ->
  gen_server:cast(?SERVER, {delete, Name}).

% Gen server hooks

%% @doc Initialize the zone cache.
-spec init([]) -> {ok, #state{}}.
init([]) ->
  ets:new(zones, [set, named_table]),
  ets:new(authorities, [set, named_table]),
  {ok, #state{parsers = []}}.

% ----------------------------------------------------------------------------------------------------
% gen_server callbacks for read operations

%% @doc Get a zone from the cache by name. Do not include record data.
handle_call({get, Name}, _From, State) ->
  NormalizedName = normalize_name(Name),
  case ets:lookup(zones, NormalizedName) of
    [{NormalizedName, Zone}] -> {reply, {ok, Zone#zone{name = NormalizedName, records = [], records_by_name=trimmed}}, State};
    _ -> {reply, {error, zone_not_found}, State}
  end;

%% @doc Get a zone from the cache by name. Include record data.
%% Currently this is only used for administrative purposes.
handle_call({get_zone_with_records, Name}, _From, State) ->
  NormalizedName = normalize_name(Name),
  case ets:lookup(zones, NormalizedName) of
    [{NormalizedName, Zone}] -> {reply, {ok, Zone}, State};
    _ -> {reply, {error, zone_not_found}, State}
  end;

%% @doc Get authority records (SOA) for a zone.
handle_call({get_authority, Name}, _From, State) ->
  find_authority(normalize_name(Name), State);

%% @doc Get delegation records (NS and associated glue records) for a zone.
handle_call({get_delegations, Name}, _From, State) ->
  case find_zone_in_cache(Name, State) of
    {ok, Zone} ->
      Records = lists:filter(fun(R) -> apply(erldns_records:match_type(?DNS_TYPE_NS), [R]) and apply(erldns_records:match_glue(Name), [R]) end, Zone#zone.records),
      {reply, {ok, Records}, State};
    Response ->
      %lager:debug("get_delegations, failed to get zone for ~p: ~p", [Name, Response]),
      {reply, Response, State}
  end;

handle_call({get_records_by_name, Name}, _From, State) ->
  case find_zone_in_cache(Name, State) of
    {ok, Zone} ->
      case dict:find(normalize_name(Name), Zone#zone.records_by_name) of
        {ok, RecordSet} -> {reply, RecordSet, State};
        _ -> {reply, [], State}
      end;
    _Response ->
      %lager:debug("get_records_by_name, failed to get zone for ~p: ~p", [Name, Response]),
      {reply, [], State}
  end;

handle_call({in_zone, Name}, _From, State) ->
  case find_zone_in_cache(Name, State) of
    {ok, Zone} ->
      {reply, internal_in_zone(Name, Zone), State};
    _ ->
      {reply, false, State}
  end;

handle_call({zone_names_and_versions}, _From, State) ->
  {reply, ets:foldl(fun({_, Zone}, NamesAndShas) -> NamesAndShas ++ [{Zone#zone.name, Zone#zone.version}] end, [], zones), State};

% ----------------------------------------------------------------------------------------------------
% gen_server callbacks for Write operations

%% @doc Write the zone into the cache.
handle_call({put, Name, Zone}, _From, State) ->
  ets:insert(zones, {normalize_name(Name), Zone}),
  {reply, ok, State}.

handle_cast({put, Name, Zone}, State) ->
  ets:insert(zones, {normalize_name(Name), Zone}),
  {noreply, State};

handle_cast({delete, Name}, State) ->
  ets:delete(zones, normalize_name(Name)),
  {noreply, State};

handle_cast(_, State) ->
  {noreply, State}.
handle_info(_Message, State) ->
  {noreply, State}.
terminate(_Reason, _State) ->
  ok.
code_change(_PreviousVersion, State, _Extra) ->
  {ok, State}.


% Internal API
internal_in_zone(Name, Zone) ->
  case dict:is_key(normalize_name(Name), Zone#zone.records_by_name) of
    true -> true;
    false ->
      case dns:dname_to_labels(Name) of
        [] -> false;
        [_] -> false;
        [_|Labels] -> internal_in_zone(dns:labels_to_dname(Labels), Zone)
      end
  end.

find_authority(Name, State) ->
  case find_zone_in_cache(Name, State) of
    {ok, Zone} -> {reply, {ok, Zone#zone.authority}, State};
    _ -> {reply, {error, authority_not_found}, State}
  end.

find_zone_in_cache(Qname, State) ->
  Name = normalize_name(Qname),
  case dns:dname_to_labels(Name) of
    [] -> {error, zone_not_found};
    [_] -> {error, zone_not_found};
    [_|Labels] ->
      case ets:lookup(zones, Name) of
        [{Name, Zone}] -> {ok, Zone};
        _ -> find_zone_in_cache(dns:labels_to_dname(Labels), State)
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
      build_named_index(Rest, dict:store(R#dns_rr.name, Records ++ [R], Idx));
    error -> build_named_index(Rest, dict:store(R#dns_rr.name, [R], Idx))
  end.

normalize_name(Name) when is_list(Name) -> string:to_lower(Name);
normalize_name(Name) when is_binary(Name) -> list_to_binary(string:to_lower(binary_to_list(Name))).
