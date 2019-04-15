%% Copyright (c) 2012-2018, DNSimple Corporation
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
-spec find_zone(dns:dname()) -> #zone{} | {error, zone_not_found} | {error, not_authoritative}.
find_zone(Qname) ->
  find_zone(erldns:normalize_name(Qname), get_authority(Qname)).

%% @doc Find a zone for a given qname.
-spec find_zone(dns:dname(), {error, any()} | {ok, dns:rr()} | [dns:rr()] | dns:rr()) -> #zone{} | {error, zone_not_found} | {error, not_authoritative}.
find_zone(Qname, {error, _}) ->
  find_zone(Qname, []);
find_zone(Qname, {ok, Authority}) ->
  find_zone(Qname, Authority);
find_zone(_Qname, []) ->
  {error, not_authoritative};
find_zone(Qname, Authorities) when is_list(Authorities) ->
  find_zone(Qname, lists:last(Authorities));
find_zone(Qname, Authority) when is_record(Authority, dns_rr) ->
  Name = erldns:normalize_name(Qname),
  case dns:dname_to_labels(Name) of
    [] -> {error, zone_not_found};
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
  NormalizedName = erldns:normalize_name(Name),
  case erldns_storage:select(zones, NormalizedName) of
    [{NormalizedName, Zone}] -> {ok, Zone#zone{name = NormalizedName, records = [], records_by_name=trimmed}};
    _ -> {error, zone_not_found}
  end.

%% @doc Get a zone for the specific name, including the records for the zone.
-spec get_zone_with_records(dns:dname()) -> {ok, #zone{}} | {error, zone_not_found}.
get_zone_with_records(Name) ->
  NormalizedName = erldns:normalize_name(Name),
  case erldns_storage:select(zones, NormalizedName) of
    [{NormalizedName, Zone}] -> {ok, Zone};
    _ -> {error, zone_not_found}
  end.

%% @doc Find the SOA record for the given DNS question.
-spec get_authority(dns:message() | dns:dname()) -> {error, no_question} | {error, authority_not_found} | {ok, dns:rr()}.
get_authority(Message) when is_record(Message, dns_message) ->
  case Message#dns_message.questions of
    [] -> {error, no_question};
    Questions -> 
      Question = lists:last(Questions),
      get_authority(Question#dns_query.name)
  end;
get_authority(Name) ->
  case find_zone_in_cache(erldns:normalize_name(Name)) of
    {ok, Zone} -> {ok, Zone#zone.authority};
    _ -> {error, authority_not_found}
  end.

%% @doc Get the list of NS and glue records for the given name. This function
%% will always return a list, even if it is empty.
-spec get_delegations(dns:dname()) -> [dns:rr()] | [].
get_delegations(Name) ->
  case find_zone_in_cache(Name) of
    {ok, Zone} ->
      lists:filter(fun(R) -> apply(erldns_records:match_type(?DNS_TYPE_NS), [R]) and apply(erldns_records:match_delegation(Name), [R]) end, Zone#zone.records);
    _ ->
      []
  end.

%% @doc Return the record set for the given dname.
-spec get_records_by_name(dns:dname()) -> [dns:rr()].
get_records_by_name(Name) ->
  case find_zone_in_cache(Name) of
    {ok, Zone} ->
      maps:get(erldns:normalize_name(Name), Zone#zone.records_by_name, []);
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
  erldns_storage:foldl(fun({_, Zone}, NamesAndShas) -> NamesAndShas ++ [{Zone#zone.name, Zone#zone.version}] end, [], zones).

% ----------------------------------------------------------------------------------------------------
% Write API

%% @doc Put a name and its records into the cache, along with a SHA which can be
%% used to determine if the zone requires updating.
%%
%% This function will build the necessary Zone record before interting.
-spec put_zone({Name, Sha, Records, Keys} | {Name, Sha, Records}) -> ok | {error, Reason :: term()}
  when Name :: binary(), Sha :: binary(), Records :: [dns:rr()], Keys :: [erldns:keyset()].
put_zone({Name, Sha, Records}) ->
    put_zone({Name, Sha, Records, []});
put_zone({Name, Sha, Records, Keys}) ->
  put_zone(erldns:normalize_name(Name), build_zone(Name, Sha, Records, Keys)).

%% @doc Put a zone into the cache and wait for a response.
-spec put_zone(binary(), erldns:zone()) -> ok | {error, Reason :: term()}.
put_zone(Name, Zone) ->
  erldns_storage:insert(zones, {erldns:normalize_name(Name), sign_zone(Zone)}).

%% @doc Remove a zone from the cache without waiting for a response.
-spec delete_zone(binary()) -> any().
delete_zone(Name) ->
  gen_server:cast(?SERVER, {delete, Name}).



% ----------------------------------------------------------------------------------------------------
% Gen server init

%% @doc Initialize the zone cache.
-spec init([]) -> {ok, #state{}}.
init([]) ->
  erldns_storage:create(schema),
  erldns_storage:create(zones),
  erldns_storage:create(authorities),
  {ok, #state{parsers = []}}.

% ----------------------------------------------------------------------------------------------------
% gen_server callbacks

handle_call(Message, _From, State) ->
  lager:debug("Received unsupported call (message: ~p)", [Message]),
  {reply, ok, State}.

handle_cast({delete, Name}, State) ->
  erldns_storage:delete(zones, erldns:normalize_name(Name)),
  {noreply, State};

handle_cast(Message, State) ->
  lager:debug("Received unsupported cast (message: ~p)", [Message]),
  {noreply, State}.

handle_info(_Message, State) ->
  {noreply, State}.

terminate(_Reason, _State) ->
  ok.

code_change(_PreviousVersion, State, _Extra) ->
  {ok, State}.


% Internal API
is_name_in_zone(Name, Zone) ->
  case maps:is_key(erldns:normalize_name(Name), Zone#zone.records_by_name) of
    true -> true;
    false ->
      case dns:dname_to_labels(Name) of
        [] -> false;
        [_] -> false;
        [_|Labels] -> is_name_in_zone(dns:labels_to_dname(Labels), Zone)
      end
  end.

find_zone_in_cache(Qname) ->
  Name = erldns:normalize_name(Qname),
  find_zone_in_cache(Name, dns:dname_to_labels(Name)).

find_zone_in_cache(_Name, []) ->
  {error, zone_not_found};
find_zone_in_cache(Name, [_|Labels]) ->
  case erldns_storage:select(zones, Name) of
    [{Name, Zone}] -> {ok, Zone};
    _ ->
      case Labels of
        [] -> {error, zone_not_found};
        _ -> find_zone_in_cache(dns:labels_to_dname(Labels))
      end
  end.

build_zone(Qname, Version, Records, Keys) ->
  RecordsByName = build_named_index(Records),
  Authorities = lists:filter(erldns_records:match_type(?DNS_TYPE_SOA), Records),
  #zone{name = Qname, version = Version, record_count = length(Records), authority = Authorities, records = Records, records_by_name = RecordsByName, keysets = Keys}.

-spec(build_named_index([#dns_rr{}]) -> #{binary() => [#dns_rr{}]}).
build_named_index(Records) ->
  Idx0 = lists:foldl(fun (R, Idx) ->
    Name = erldns:normalize_name(R#dns_rr.name),
    maps:update_with(Name, fun (RR) -> [R | RR] end, [R], Idx)
  end, #{}, Records),
  maps:map(fun (_K, V) -> lists:reverse(V) end, Idx0).

-spec(sign_zone(erldns:zone()) -> erldns:zone()).
sign_zone(Zone = #zone{keysets = []}) ->
  Zone;
sign_zone(Zone) ->
  lager:debug("Signing zone (name: ~p)", [Zone#zone.name]),
  DnskeyRRs = lists:filter(erldns_records:match_type(?DNS_TYPE_DNSKEY), Zone#zone.records),
  KeyRRSigRecords = lists:flatten(lists:map(erldns_dnssec:key_rrset_signer(Zone#zone.name, DnskeyRRs), Zone#zone.keysets)),

  verify_zone(Zone, DnskeyRRs, KeyRRSigRecords),

  % TODO: remove wildcard signatures as they will not be used but are taking up space
  ZoneRRSigRecords = lists:flatten(lists:map(erldns_dnssec:zone_rrset_signer(Zone#zone.name, lists:filter(fun(RR) -> (RR#dns_rr.type =/= ?DNS_TYPE_DNSKEY) end, Zone#zone.records)), Zone#zone.keysets)),
  build_zone(Zone#zone.name, Zone#zone.version, Zone#zone.records ++ KeyRRSigRecords ++ rewrite_soa_rrsig_ttl(Zone#zone.records, ZoneRRSigRecords -- lists:filter(erldns_records:match_wildcard(), ZoneRRSigRecords)), Zone#zone.keysets).

-spec(verify_zone(erldns:zone(), [dns:rr()], [dns:rr()]) -> boolean()).
verify_zone(Zone, DnskeyRRs, KeyRRSigRecords) ->
  lager:debug("Verify zone (name: ~p)", [Zone#zone.name]),
  case lists:filter(fun(RR) -> RR#dns_rr.data#dns_rrdata_dnskey.flags =:= 257 end, DnskeyRRs) of
    [] -> false;
    KSKs -> 
      lager:debug("KSKs: ~p", [KSKs]),
      KSKDnskey = lists:last(KSKs),
      RRSig = lists:last(KeyRRSigRecords),
      lager:debug("Attempting to verify RRSIG (key: ~p)", [KSKDnskey]),
      VerifyResult = dnssec:verify_rrsig(RRSig, DnskeyRRs, [KSKDnskey], []),
      lager:debug("KSK verification (verified?: ~p)", [VerifyResult]),
      VerifyResult
  end.

rewrite_soa_rrsig_ttl(ZoneRecords, RRSigRecords) ->
  SoaRR = lists:last(lists:filter(erldns_records:match_type(?DNS_TYPE_SOA), ZoneRecords)),
  lists:map(
    fun(RR) ->
        case RR#dns_rr.type of
          ?DNS_TYPE_RRSIG -> erldns_records:minimum_soa_ttl(RR, SoaRR#dns_rr.data);
          _ -> RR
        end
    end, RRSigRecords).
