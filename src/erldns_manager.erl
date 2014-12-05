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

-record(state, {}).

%%%===================================================================
%%% API
%%%===================================================================
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).
%%%===================================================================
%%% gen_server callbacks
%%%===================================================================
init([]) ->
    {ok, #state{}}.

handle_call(_Request, _From, State) ->
    {reply, ok, State}.

handle_cast({send_notify, {_BindIP, _DestinationIP, _Port, _ZoneName, _ZoneClass} = Args}, State) ->
    Spec = {{erldns_zone_transfer_worker, now()}, {erldns_zone_transfer_worker, start_link, [send_notify, Args]},
            temporary, 5000, worker, [erldns_zone_transfer_worker]},
    supervisor:start_child(erldns_zone_transfer_sup, Spec),
    {noreply, State};
handle_cast({handle_notify, {_Message, {_ClientIP, _Port}, _ServerIP} = Args}, State) ->
    Spec = {{erldns_zone_transfer_worker, now()}, {erldns_zone_transfer_worker, start_link, [handle_notify, Args]},
        temporary, 5000, worker, [erldns_zone_transfer_worker]},
    supervisor:start_child(erldns_zone_transfer_sup, Spec),
    {noreply, State};
handle_cast(_Request, State) ->
    erldns_log:info("Some other message: ~p", [_Request]),
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================


%% handle_notify(_DecodedMessage, _ClientIP, _ServerIP) ->
%%     %% Check is the serial in the SOA is changed.
%%     %%If serial is changed, request AXFR
%%     %%Else, drop it.
%%     ok.

%% handle_decoded_tcp_message(DecodedMessage, Socket, ClientIP, ServerIP) when DecodedMessage#dns_message.oc =:= 4 ->
%%     erldns_log:info("Handling a NOTIFY!"),
%%     spawn_link(fun() -> handle_notify(DecodedMessage, ClientIP, ServerIP) end),
%%     erldns_events:notify({start_handle, tcp, [{host, ClientIP}]}),
%%     Response = erldns_handler:handle(DecodedMessage, {tcp, ClientIP, ServerIP}),
%%     erldns_events:notify({end_handle, tcp, [{host, ClientIP}]}),
%%     case erldns_encoder:encode_message(Response) of
%%         {false, EncodedMessage} ->
%%             send_tcp_message(Socket, EncodedMessage);
%%         {true, EncodedMessage, Message} when is_record(Message, dns_message) ->
%%             send_tcp_message(Socket, EncodedMessage);
%%         {false, EncodedMessage, _TsigMac} ->
%%             send_tcp_message(Socket, EncodedMessage);
%%         {true, EncodedMessage, _TsigMac, _Message} ->
%%             send_tcp_message(Socket, EncodedMessage)
%%     end;