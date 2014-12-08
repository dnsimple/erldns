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
    Pid = self(),
    gen_server:cast(Pid, {Operation, Args}),
    {ok, #state{}}.

handle_call(_Request, _From, State) ->
    {reply, ok, State}.

handle_cast({send_notify, {BindIP, DestinationIP, Port, ZoneName, ZoneClass} = _Args}, State) ->
    send_notify(BindIP, DestinationIP, Port, ZoneName, ZoneClass),
    {noreply, State};
handle_cast({handle_notify, {Message, ClientIP, ServerIP}}, State) ->
    handle_notify(Message, ClientIP, ServerIP),
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
    {ok, _Recv} = case erldns_encoder:encode_message(Packet) of
                     {false, EncodedMessage} ->
                         send_tcp_message(BindIP, {DestinationIP, Port}, EncodedMessage);
                     {true, EncodedMessage, Message} when is_record(Message, dns_message) ->
                         send_tcp_message(BindIP, {DestinationIP, Port}, EncodedMessage);
                     {false, EncodedMessage, _TsigMac} ->
                         send_tcp_message(BindIP, {DestinationIP, Port}, EncodedMessage);
                     {true, EncodedMessage, _TsigMac, _Message} ->
                         send_tcp_message(BindIP, {DestinationIP, Port}, EncodedMessage)
                 end,
    erldns_log:info("Recived NOTIFY ack from slave ~p", [dns:decode_message(_Recv)]),
    exit(normal).

handle_notify(Message, ClientIP, ServerIP) ->
    %% Get the zone in your cache
    ZoneName0 = hd(Message#dns_message.questions),
    ZoneName = normalize_name(ZoneName0#dns_query.name),
    {ok, Zone} = erldns_zone_cache:get_zone_with_records(ZoneName),
    SOA = get_soa(ZoneName, Zone#zone.records),
    %% Check if the sender is authorative to send a notify request before doing anything
    case lists:member(ClientIP, Zone#zone.allow_notify) of
        false ->
            erldns_log:warning("sender ~p not allowed to NOTIFY", [ClientIP]),
            erldns_log:warning("Allowed to notify: ~p", [Zone#zone.allow_notify]),
            exit(normal);
        _ ->
            ok
    end,
    %% Request SOA from master
    Request = #dns_message{id = dns:random_id(),
        oc = ?DNS_OPCODE_QUERY,
        rd = true,
        qc = 1,
        questions = [#dns_query{name = ZoneName, class = ?DNS_CLASS_ANY, type = ?DNS_TYPE_SOA}]},
    {ok, Recv} = case erldns_encoder:encode_message(Request) of
                     {false, EncodedMessage} ->
                         send_tcp_message(ServerIP, hd(AllowedNotify), EncodedMessage);
                     {true, EncodedMessage, Message} when is_record(Message, dns_message) ->
                         send_tcp_message(ServerIP, hd(AllowedNotify), EncodedMessage);
                     {false, EncodedMessage, _TsigMac} ->
                         send_tcp_message(ServerIP, hd(AllowedNotify),EncodedMessage);
                     {true, EncodedMessage, _TsigMac, _Message} ->
                         send_tcp_message(ServerIP, hd(AllowedNotify), EncodedMessage)
                 end,
    erldns_log:info("Recieved SOA from master: ~p", [dns:decode_message(Recv)]),
    Authority = dns:decode_message(Recv),
    %% Check the serial and send axfr request if you are the authority for it
    StoredSerial = SOA#dns_rr.data#dns_rrdata_soa.serial,
    MasterSerial0 = hd(Authority#dns_message.answers),
    MasterSerial = MasterSerial0#dns_rr.data#dns_rrdata_soa.serial,
    case StoredSerial =/= MasterSerial of
        true ->
            %% TODO dont hard code port
            send_axfr(ZoneName, ServerIP, ClientIP, 8053);
        false ->
            lager:info("Dont need to: ~p == ~p", [StoredSerial, MasterSerial]),
            ok
    end,
    exit(normal).

send_axfr(ZoneName, BindIP, DestinationIP, Port) ->
    lager:info("Sending an axfr request!"),
%%     {dns_message, 27085, false,0, false, false, true, false, true, false,0, 1,0,0,1, [{dns_query, <<"example.com">>, 1,6}], [],[], [{dns_optrr, 4096,0, 0, false, []}]}
    Packet =  #dns_message{id = dns:random_id(),
                            oc = ?DNS_OPCODE_QUERY,
                            rd = true,
                            ad = true,
                            rc = ?DNS_RCODE_NOERROR,
                            aa = true,
                            qc = 1,
                            adc = 1,
                            questions = [#dns_query{name = ZoneName, class = ?DNS_CLASS_IN, type = ?DNS_TYPE_AXFR}]},
    {ok, _Recv} = case erldns_encoder:encode_message(Packet) of
                      {false, EncodedMessage} ->
                          send_tcp_message(BindIP, {DestinationIP, Port}, EncodedMessage);
                      {true, EncodedMessage, Message} when is_record(Message, dns_message) ->
                          send_tcp_message(BindIP, {DestinationIP, Port}, EncodedMessage);
                      {false, EncodedMessage, _TsigMac} ->
                          send_tcp_message(BindIP, {DestinationIP, Port}, EncodedMessage);
                      {true, EncodedMessage, _TsigMac, _Message} ->
                          send_tcp_message(BindIP, {DestinationIP, Port}, EncodedMessage)
                  end,
    erldns_log:info("Recived NOTIFY ack from slave ~p", [dns:decode_message(_Recv)]),
    exit(normal).

%%%===================================================================
%%% Utility functions
%%%===================================================================
%% RFC 1996
%% 3.5. If TCP is used, both master and slave must continue to offer
%% name service during the transaction, even when the TCP transaction is
%% not making progress.  The NOTIFY request is sent once, and a
%% "timeout" is said to have occurred if no NOTIFY response is received
%% within a reasonable interval.
-spec send_tcp_message(inet:ip_address(), {inet:ip_address(), inet:port_number()}, binary()) -> ok | {error, Reason :: term()}.
send_tcp_message(BindIP, {DestinationIP, Port}, EncodedMessage) ->
    BinLength = byte_size(EncodedMessage),
    TcpEncodedMessage = <<BinLength:16, EncodedMessage/binary>>,
    send_recv(BindIP, DestinationIP, Port, TcpEncodedMessage).

send_recv(BindIP, DestinationIP, Port, TcpEncodedMessage) ->
    {ok, Socket} = gen_tcp:connect(DestinationIP, Port, [binary, {active, false}, {ip, BindIP}]),
    ok = gen_tcp:send(Socket, TcpEncodedMessage),
    %% Remove the size header.
    {ok, <<_Len:16, Res/binary>>} = gen_tcp:recv(Socket, 0),
    ok = gen_tcp:close(Socket),
    {ok, Res}.

normalize_name(Name) when is_list(Name) -> string:to_lower(Name);
normalize_name(Name) when is_binary(Name) -> list_to_binary(string:to_lower(binary_to_list(Name))).

-spec get_soa([#dns_rr{}], binary()) -> #dns_rr{}.
get_soa(ZoneName, DNSRRList) ->
    get_soa(ZoneName, DNSRRList, []).

get_soa(_ZoneName, [], SOA) ->
    SOA;
get_soa( ZoneName, [#dns_rr{data = Data} = Head | Tail], SOA) ->
    case Data of
        #dns_rrdata_soa{} ->
            get_soa(ZoneName, Tail, Head);
        _ ->
            get_soa(ZoneName, Tail, SOA)
    end.