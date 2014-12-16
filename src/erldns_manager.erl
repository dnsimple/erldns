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

%% @doc Manages zone transfers (NOTIFY and AXFRs)

-module(erldns_manager).

-behaviour(gen_server).

-include_lib("dns/include/dns.hrl").
-include("erldns.hrl").

%% API
-export([start_link/0]).

%% gen_server callbacks
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

-define(SERVER, ?MODULE).
-define(REFRESH_INTERVAL, 5000).
%% Helper macro for declaring children of supervisor
-define(TRANSFER_WORKER(Mod, Args),
        {{erldns_zone_transfer_worker, now()}, {erldns_zone_transfer_worker, start_link, [Mod, Args]},
         temporary, 5000, worker, [erldns_zone_transfer_worker]}).
-record(state, {zone_expirations, orddict_size}).

%%%===================================================================
%%% API
%%%===================================================================
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).
%%%===================================================================
%%% gen_server callbacks
%%%===================================================================
init([]) ->
    %%Set up orddict and put it in state
    Orddict = setup_zone_expiration_orddict(),
    {ok, #state{zone_expirations = Orddict, orddict_size = orddict:size(Orddict)}, 0}.

handle_call(_Request, _From, State) ->
    {reply, ok, State}.

handle_cast({send_notify, {_BindIP, _DestinationIP, _ZoneName, _ZoneClass} = Args}, State) ->
    Spec = ?TRANSFER_WORKER(send_notify, Args),
    supervisor:start_child(erldns_zone_transfer_sup, Spec),
    {noreply, State, ?REFRESH_INTERVAL};
handle_cast({handle_notify, {_Message, _ClientIP, _ServerIP} = Args}, State) ->
    Spec = ?TRANSFER_WORKER(handle_notify, Args),
    supervisor:start_child(erldns_zone_transfer_sup, Spec),
    {noreply, State, ?REFRESH_INTERVAL};
handle_cast({send_axfr, {_ZoneName, _ServerIP} = Args}, State) ->
    Spec = ?TRANSFER_WORKER(send_axfr, Args),
    supervisor:start_child(erldns_zone_transfer_sup, Spec),
    {noreply, State, ?REFRESH_INTERVAL};
handle_cast({send_zone_name_request, {_Bin, {_MasterIP, _Port}, _BindIP} = Args}, State) ->
    erldns_log:info("send zone name request args: ~p", [Args]),
    Spec = ?TRANSFER_WORKER(send_zone_name_request, Args),
    supervisor:start_child(erldns_zone_transfer_sup, Spec),
    {noreply, State, ?REFRESH_INTERVAL};
handle_cast(_Request, State) ->
    erldns_log:info("Some other message: ~p", [_Request]),
    {noreply, State, ?REFRESH_INTERVAL}.

%% @doc Every interval it checks for entry in orrdict to see if zone is expired, if not it restarts
%% timer with the same order, else it sends an axfr to the associated master, reorders the
%% dict and restarts the timer.
%% @end
handle_info(timeout, #state{zone_expirations = Orddict, orddict_size = Size} = State) when Size > 0 ->
    Before = now(),
    Timestamp = timestamp(),
    NewOrddict = case hd(orddict:to_list(Orddict)) of
                     {Expiration, ListOfExpiredZones} when Expiration < Timestamp ->
                         [gen_server:cast(erldns_manager, {send_axfr, Args})
                          || Args <- ListOfExpiredZones],
                         create_new_zone_expiration_orddict(Expiration, Orddict, ListOfExpiredZones);
                     {Expiration, _ListOfExpiredZone} when Expiration >= Timestamp ->
                         Orddict
                 end,
    TimeSpentMs = timer:now_diff(now(), Before) div 1000,
    {noreply, State#state{zone_expirations = NewOrddict, orddict_size = orddict:size(NewOrddict)},
     ?REFRESH_INTERVAL + TimeSpentMs};
handle_info(timeout, State)  ->
    %%TODO Should we attempt a refresh? And check if there are now zones in our authroity we should watch?
    {noreply, State, ?REFRESH_INTERVAL};
handle_info(_Info, State) ->
    {noreply, State, ?REFRESH_INTERVAL}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State, ?REFRESH_INTERVAL}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
%% @doc This function creates a orrdict for the zones the slave  has. This orddict serves as
%% a data structure that stores expiration as a key with the list of arguments necessary to
%% initiate a zone transfer (AXFR) for the expired zone(s).
%% @end
-spec setup_zone_expiration_orddict() -> orddict:orddict().
setup_zone_expiration_orddict() ->
    %% Get the bind IP we will use to send the AXFR
    {ok, IFAddrs} = inet:getifaddrs(),
    MountedIPAddresses = [begin
                              {addr, Addr} = lists:keyfind(addr, 1, List),
                              Addr
                          end || {_, List} <- IFAddrs],
    NewOrrdict = lists:foldl(
                   fun({ZoneName, _ZoneVersion}, Orrdict) ->
                           {ok, #zone{allow_transfer = AllowTransfer, notify_source = NotifySource,
                                      authority = [#dns_rr{data = ZoneAuth}]}}
                               = erldns_zone_cache:get_zone_with_records(ZoneName),
                           case AllowTransfer of
                               [] ->
                                   Orrdict;
                               _ ->
                                   MountedIP = hd(lists:sort([IP || IP <- MountedIPAddresses,
                                                                    lists:member(IP, AllowTransfer)])),
                                   case NotifySource =:= MountedIP of
                                       true ->
                                           %% We are the zone Authority, we don't need to keep
                                           %% track of this zone.
                                           Orrdict;
                                       false ->
                                           %% We are slave of a zone, we need to keep track of it
                                           %% and send afxr when it expires
                                           Expiration = ZoneAuth#dns_rrdata_soa.expire + timestamp(),
                                           ArgsToSendAXFR = {ZoneName, MountedIP},
                                           orddict:append(Expiration, ArgsToSendAXFR, Orrdict)
                                   end
                           end
                   end,
                   orddict:new(),
                   erldns_zone_cache:zone_names_and_versions()),
    NewOrrdict.

%% @doc This function takes the expiration of the zone list as the key, and deletes that entry in the
%% orddict. Then appends a refreshed expiration in the correct order of the dict.
%% @end
-spec create_new_zone_expiration_orddict(integer(), orddict:orddict(),
                                         [{ZoneName :: binary(), BindIP :: inet:ip_address()}]) ->
                                                orddict:orddict().
create_new_zone_expiration_orddict(ExpirationKey, Orddict, ListOfExpiredZones) ->
    Orddict0 = orddict:erase(ExpirationKey, Orddict),
    lists:flatten([orddict:append(get_expiration(ZoneName), Args, Orddict0)
                   || {ZoneName, _ServerIP} = Args <- ListOfExpiredZones]).

%% @doc Gets the expiration of the given zone name
-spec get_expiration(binary()) -> integer().
get_expiration(ZoneName) ->
    {ok, #zone{} = Zone} = erldns_zone_cache:get_zone_with_records(ZoneName),
    [#dns_rr{data = #dns_rrdata_soa{expire = Expire}}] = Zone#zone.authority,
    Expire + timestamp().

timestamp() ->
    {TM, TS, _} = os:timestamp(),
    (TM * 1000000) + TS.
