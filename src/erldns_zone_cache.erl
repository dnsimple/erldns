-module(erldns_zone_cache).

-behavior(gen_server).

-include("dns.hrl").
-include("erldns.hrl").

% API
-export([start_link/0, get/1, put/2, get_authority/1, put_authority/2]).
-export([in_zone/2, find_authority/1, find_zone/1, find_zone/2]).

% Internal API
-export([build_named_index/1]).

% Gen server hooks
-export([init/1,
	 handle_call/3,
	 handle_cast/2,
	 handle_info/2,
	 terminate/2,
	 code_change/3
       ]).

-define(SERVER, ?MODULE).

-record(state, {zones}).

%% Public API
start_link() ->
  gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

get(Name) ->
  gen_server:call(?SERVER, {get, Name}).
put(Name, Zone) ->
  gen_server:call(?SERVER, {put, Name, Zone}).
get_authority(Message) when is_record(Message, dns_message) ->
  case Message#dns_message.questions of
    [] -> [];
    Questions -> 
      Question = lists:last(Questions),
      get_authority(Question#dns_query.name)
  end;
get_authority(Name) ->
  gen_server:call(?SERVER, {get_authority, Name}).
put_authority(Name, Authority) ->
  gen_server:call(?SERVER, {put_authority, Name, Authority}).

in_zone(Name, Zone) ->
  case dict:is_key(Name, Zone#zone.records_by_name) of
    true -> true;
    false ->
      case dns:dname_to_labels(Name) of
        [] -> false;
        [_] -> false;
        [_|Labels] -> in_zone(dns:labels_to_dname(Labels), Zone)
      end
  end.

%% Gen server hooks
init([]) ->
  ets:new(zone_cache, [set, named_table]),
  ets:new(authority_cache, [set, named_table]),
  {ok, #state{}}.

handle_call({get, Name}, _From, State) ->
  case ets:lookup(zone_cache, normalize_name(Name)) of
    [{Name, {Zone}}] -> {reply, {ok, Zone}, State};
    _ -> {reply, {error, zone_not_found}, State}
  end;
handle_call({put, Name, Zone}, _From, State) ->
  ets:insert(zone_cache, {Name, {Zone}}),
  {reply, ok, State};
handle_call({get_authority, Name}, _From, State) ->
  case ets:lookup(authority_cache, normalize_name(Name)) of
    [{Name, {Authority}}] -> 
      {reply, {ok, Authority}, State};
    _ -> 
      case load_authority(Name) of
        [] -> {reply, {error, authority_not_found}, State};
        Authority -> {reply, {ok, Authority}, State}
      end
  end;
handle_call({put_authority, Name, Authority}, _From, State) ->
  ets:insert(authority_cache, {Name, {Authority}}),
  {reply, ok, State}.

handle_cast(_Message, State) ->
  {noreply, State}.
handle_info(_Message, State) ->
  {noreply, State}.
terminate(_Reason, _State) ->
  ets:delete(zone_cache),
  ets:delete(authority_cache),
  ok.
code_change(_PreviousVersion, State, _Extra) ->
  {ok, State}.

% Internal API%

%% Get the SOA authority for the current query.
find_authority(Qname) -> 
  case dns:dname_to_labels(Qname) of
    [] -> {error, authority_not_found};
    [_] -> {error, authority_not_found};
    [_|Labels] ->
      Name = dns:labels_to_dname(Labels),
      case find_authority(Name) of
        {ok, Authority} -> Authority;
        {error, authority_not_found} -> find_authority(Name)
      end
  end.

load_authority(Qname) ->
  load_authority(Qname, [F([normalize_name(Qname)]) || F <- soa_functions()]).

load_authority(_Qname, []) -> [];
load_authority(Qname, Authorities) -> 
  Authority = lists:last(Authorities),
  ets:insert(authority_cache, {normalize_name(Qname), {Authority}}),
  Authority.

% Find the zone for the given name.
find_zone(Qname) ->
  Authority = erldns_metrics:measure(none, ?MODULE, get_authority, [Qname]),
  find_zone(normalize_name(Qname), Authority).

find_zone(_Qname, []) ->
  {error, not_authoritative};
find_zone(Qname, Authority) when is_list(Authority) -> find_zone(Qname, lists:last(Authority));
find_zone(Qname, Authority) when is_record(Authority, dns_rr) ->
  lager:info("Finding zone ~p (Authority: ~p)", [Qname, Authority]),
  Name = normalize_name(Qname),
  case dns:dname_to_labels(Name) of
    [] -> {error, zone_not_found};
    [_] -> {error, zone_not_found};
    [_|Labels] ->
      case erldns_zone_cache:get(Name) of
        {ok, Zone} -> Zone;
        {error, zone_not_found} -> 
          case Name =:= Authority#dns_rr.name of
            true -> make_zone(Name);
            false -> find_zone(dns:labels_to_dname(Labels), Authority)
          end
      end
  end.

make_zone(Qname) ->
  lager:info("Constructing new zone for ~p", [Qname]),
  DbRecords = erldns_metrics:measure(Qname, erldns_pgsql, lookup_records, [normalize_name(Qname)]),
  Records = lists:usort(lists:flatten(lists:map(fun(R) -> erldns_pgsql_responder:db_to_record(Qname, R) end, DbRecords))),
  RecordsByName = erldns_metrics:measure(Qname, ?MODULE, build_named_index, [Records]),
  Zone = #zone{records = Records, records_by_name = RecordsByName},
  erldns_zone_cache:put(Qname, Zone),
  Zone.

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

%% Build a list of functions for looking up SOA records based on the
%% registered responders.
soa_functions() ->
  lists:map(fun(M) -> fun M:get_soa/1 end, erldns_handler:get_responder_modules()).
