-module(erldns_zone_cache).

-behavior(gen_server).

-include("dns.hrl").
-include("erldns.hrl").

% API
-export([start_link/0]).
-export([find_zone/1, find_zone/2]).
-export(
  [
    get_zone/1,
    put_zone/1,
    put_zone/2,
    put_zone_async/1,
    put_zone_async/2,
    delete_zone/1,
    get_authority/1,
    get_delegations/1,
    get_records_by_name/1,
    in_zone/1,
    zone_names_and_shas/0
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

-record(state, {parsers}).

%% Public API
start_link() ->
  gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

find_zone(Qname) ->
  find_zone(normalize_name(Qname), get_authority(Qname)).

find_zone(Qname, {error, _}) -> find_zone(Qname, []);
find_zone(Qname, {ok, Authority}) -> find_zone(Qname, Authority);
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

get_zone(Name) ->
  gen_server:call(?SERVER, {get, Name}).

put_zone({Name, Sha, Records}) ->
  gen_server:call(?SERVER, {put, Name, build_zone(Name, Sha, Records)}).

put_zone(Name, Zone) ->
  gen_server:call(?SERVER, {put, Name, Zone}).

put_zone_async({Name, Sha, Records}) ->
  gen_server:cast(?SERVER, {put, Name, build_zone(Name, Sha, Records)}).

put_zone_async(Name, Zone) ->
  gen_server:cast(?SERVER, {put, Name, Zone}).

delete_zone(Name) ->
  gen_server:cast(?SERVER, {delete, Name}).

get_authority(Message) when is_record(Message, dns_message) ->
  case Message#dns_message.questions of
    [] -> [];
    Questions -> 
      Question = lists:last(Questions),
      get_authority(Question#dns_query.name)
  end;
get_authority(Name) ->
  gen_server:call(?SERVER, {get_authority, Name}).

get_delegations(Name) ->
  Result = gen_server:call(?SERVER, {get_delegations, Name}),
  case Result of
    {ok, Delegations} -> Delegations;
    _ -> []
  end.

get_records_by_name(Name) ->
  gen_server:call(?SERVER, {get_records_by_name, Name}).

in_zone(Name) ->
  gen_server:call(?SERVER, {in_zone, Name}).

zone_names_and_shas() ->
  gen_server:call(?SERVER, {zone_names_and_shas}).

%% Gen server hooks
init([]) ->
  ets:new(zones, [set, named_table]),
  ets:new(authorities, [set, named_table]),
  {ok, #state{parsers = []}}.

handle_call({get, Name}, _From, State) ->
  NormalizedName = normalize_name(Name),
  case ets:lookup(zones, NormalizedName) of
    [{NormalizedName, Zone}] -> {reply, {ok, Zone#zone{name = NormalizedName, records = [], records_by_name=trimmed}}, State};
    _ -> {reply, {error, zone_not_found}, State}
  end;

handle_call({put, Name, Zone}, _From, State) ->
  ets:insert(zones, {normalize_name(Name), Zone}),
  {reply, ok, State};

handle_call({get_delegations, Name}, _From, State) ->
  case find_zone_in_cache(Name, State) of
    {ok, Zone} ->
      Records = lists:filter(fun(R) -> apply(erldns_records:match_type(?DNS_TYPE_NS), [R]) and apply(erldns_records:match_glue(Name), [R]) end, Zone#zone.records),
      {reply, {ok, Records}, State};
    Response ->
      %lager:debug("get_delegations, failed to get zone for ~p: ~p", [Name, Response]),
      {reply, Response, State}
  end;

handle_call({get_authority, Name}, _From, State) ->
  find_authority(normalize_name(Name), State);

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

handle_call({zone_names_and_shas}, _From, State) ->
  {reply, ets:foldl(fun({_, Zone}, NamesAndShas) -> NamesAndShas ++ [{Zone#zone.name, Zone#zone.sha}] end, [], zones), State}.

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

build_zone(Qname, Sha, Records) ->
  RecordsByName = build_named_index(Records),
  Authorities = lists:filter(erldns_records:match_type(?DNS_TYPE_SOA), Records),
  #zone{name = Qname, sha = Sha, record_count = length(Records), authority = Authorities, records = Records, records_by_name = RecordsByName}.

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

%% Various matching functions.


