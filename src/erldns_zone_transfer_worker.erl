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

-module(erldns_zone_transfer_worker).


-behaviour(gen_server).

-include_lib("dns/include/dns.hrl").
-include("erldns.hrl").

%% API
-export([start_link/2]).

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
start_link(Operation, Args) ->
    gen_server:start_link(?MODULE, [Operation, Args], []).
%%%===================================================================
%%% gen_server callbacks
%%%===================================================================
init([Operation, Args]) ->
    gen_server:cast(self(), {Operation, Args}),
    {ok, #state{}}.

handle_call(_Request, _From, State) ->
    {reply, ok, State}.

handle_cast({send_notify, {BindIP, DestinationIP, Port, ZoneName, ZoneClass} = _Args}, State) ->
    send_notify(BindIP, DestinationIP, Port, ZoneName, ZoneClass),
    {noreply, State};
handle_cast(_Request, State) ->
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
%% @doc Sends the notify message to the given nameservers. Restrict to TCP to allow proper query throttling.
-spec send_notify(inet:ip_address(), inet:ip_address(), inet:port_number(), binary(), dns:class()) -> ok.
send_notify(BindIP, DestinationIP, Port, ZoneName, ZoneClass) ->
    Packet =  #dns_message{id = dns:random_id(),
        oc = ?DNS_OPCODE_NOTIFY,
        rc = ?DNS_RCODE_NOERROR,
        aa = true,
        qc = 1,
        questions = [#dns_query{name = ZoneName, class = ZoneClass, type = ?DNS_TYPE_SOA}]},
    lager:info("Packet ~p", [Packet]),
    case erldns_encoder:encode_message(Packet) of
        {false, EncodedMessage} ->
            send_tcp_message(BindIP, DestinationIP, Port, EncodedMessage);
        {true, EncodedMessage, Message} when is_record(Message, dns_message) ->
            send_tcp_message(BindIP, DestinationIP, Port, EncodedMessage);
        {false, EncodedMessage, _TsigMac} ->
            send_tcp_message(BindIP, DestinationIP, Port, EncodedMessage);
        {true, EncodedMessage, _TsigMac, _Message} ->
            send_tcp_message(BindIP, DestinationIP, Port, EncodedMessage)
    end,
    exit(normal).

%% send_axfr() ->
%%     ok.

%% RFC 1996
%% 3.5. If TCP is used, both master and slave must continue to offer
%% name service during the transaction, even when the TCP transaction is
%% not making progress.  The NOTIFY request is sent once, and a
%% "timeout" is said to have occurred if no NOTIFY response is received
%% within a reasonable interval.
-spec send_tcp_message(inet:ip_address(), inet:ip_address(), inet:port_number(), binary()) -> ok | {error, Reason :: term()}.
send_tcp_message(BindIP, DestinationIP, Port, EncodedMessage) ->
    BinLength = byte_size(EncodedMessage),
    TcpEncodedMessage = <<BinLength:16, EncodedMessage/binary>>,
    send_recv(BindIP, DestinationIP, Port, TcpEncodedMessage).

send_recv(BindIP, DestinationIP, Port, TcpEncodedMessage) ->
    {ok, Socket} = gen_tcp:connect(DestinationIP, Port, [binary, {active, false}, {ip, BindIP}]),
    ok = gen_tcp:send(Socket, TcpEncodedMessage),
    {ok, Packet} =  gen_tcp:recv(Socket, 0, 5000),
    lager:info("Got it: ~p", [dns:decode_message(Packet)]),
    gen_tcp:close(Socket).

