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
-export([query_for_records/3]).
-export([send_axfr/3]).

%% gen_server callbacks
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

-record(state, {}).

%%%===================================================================
%%% API
%%%===================================================================
start_link(Operation, Args) ->
    gen_server:start_link(?MODULE, [Operation, Args], []).

-spec query_for_records(inet:ip_address(), inet:ip_address(), [dns:rr()]) -> dns:answers().
query_for_records(MasterIP, BindIP, DNSRRList) ->
    Questions = build_questions(DNSRRList),
    query_server_for_answers(MasterIP, BindIP, Questions).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================
init([Operation, Args]) ->
    Pid = self(),
    gen_server:cast(Pid, {Operation, Args}),
    {ok, #state{}}.

handle_call(_Request, _From, State) ->
    {reply, ok, State}.

handle_cast({send_zone_name_request, {Bin, {MasterIP, Port}, BindIP}}, State) ->
    send_zone_name_request(Bin, MasterIP, Port, BindIP),
    {noreply, State};
handle_cast({send_notify, {BindIP, DestinationIP, ZoneName, ZoneClass} = _Args}, State) ->
    send_notify(BindIP, DestinationIP, ZoneName, ZoneClass),
    {noreply, State};
handle_cast({handle_notify, {Message, ClientIP, ServerIP}}, State) ->
    handle_notify(Message, ClientIP, ServerIP),
    {noreply, State};
handle_cast({send_axfr, {ZoneName, BindIP}}, State) ->
    send_axfr(ZoneName, BindIP),
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
send_zone_name_request(Bin, MasterIP, Port, BindIP) ->
    {ok, Socket} = gen_tcp:connect(MasterIP, Port, [binary, {active, false}, {ip, BindIP}]),
    ok = gen_tcp:send(Socket, Bin),
    %% Extract the size header
    {ok, Zones} = gen_tcp:recv(Socket, 0),
    ok = gen_tcp:close(Socket),
    [send_startup_zone_request(Zone, BindIP, MasterIP) || Zone <- binary_to_term(Zones)].

%% @doc Sends the notify message to the given nameservers. Restrict to TCP to allow proper query throttling.
-spec send_notify(inet:ip_address(), inet:ip_address(), binary(), dns:class()) -> ok.
send_notify(BindIP, DestinationIP, ZoneName, ZoneClass) ->
    Packet =  #dns_message{id = dns:random_id(),
                           oc = ?DNS_OPCODE_NOTIFY,
                           rc = ?DNS_RCODE_NOERROR,
                           aa = true,
                           qc = 1,
                           questions = [#dns_query{name = ZoneName, class = ZoneClass,
                                                   type = ?DNS_TYPE_SOA}]},
    {ok, _Recv} = case erldns_encoder:encode_message(Packet) of
                      {false, EncodedMessage} ->
                          send_tcp_message(BindIP, DestinationIP, EncodedMessage);
                      {true, EncodedMessage, Message} when is_record(Message, dns_message) ->
                          send_tcp_message(BindIP, DestinationIP, EncodedMessage);
                      {false, EncodedMessage, _TsigMac} ->
                          send_tcp_message(BindIP, DestinationIP, EncodedMessage);
                      {true, EncodedMessage, _TsigMac, _Message} ->
                          send_tcp_message(BindIP, DestinationIP, EncodedMessage)
                  end,
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
                           questions = [#dns_query{name = ZoneName, class = ?DNS_CLASS_ANY,
                                                   type = ?DNS_TYPE_SOA}]},
    {ok, Recv} = case erldns_encoder:encode_message(Request) of
                     {false, EncodedMessage} ->
                         send_tcp_message(ServerIP, ClientIP, EncodedMessage);
                     {true, EncodedMessage, Message} when is_record(Message, dns_message) ->
                         send_tcp_message(ServerIP, ClientIP, EncodedMessage);
                     {false, EncodedMessage, _TsigMac} ->
                         send_tcp_message(ServerIP, ClientIP, EncodedMessage);
                     {true, EncodedMessage, _TsigMac, _Message} ->
                         send_tcp_message(ServerIP, ClientIP, EncodedMessage)
                 end,
    Authority = dns:decode_message(Recv),
    %% Check the serial and send axfr request if you are the authority for it
    StoredSerial = SOA#dns_rr.data#dns_rrdata_soa.serial,
    MasterSerial0 = hd(Authority#dns_message.answers),
    MasterSerial = MasterSerial0#dns_rr.data#dns_rrdata_soa.serial,
    case StoredSerial =/= MasterSerial of
        true ->
            send_axfr(ZoneName, ServerIP, ClientIP);
        false ->
            ok
    end,
    exit(normal).

send_axfr(ZoneName, BindIP) ->
    {ok, Zone} = erldns_zone_cache:get_zone(ZoneName),
    case BindIP =/= Zone#zone.notify_source of
        true ->
            send_axfr(ZoneName, BindIP, Zone#zone.notify_source);
        false ->
            exit(normal)
    end.

send_axfr(ZoneName, BindIP, DestinationIP) ->
    Packet =  #dns_message{id = dns:random_id(),
                           oc = ?DNS_OPCODE_QUERY,
                           rd = true,
                           ad = true,
                           rc = ?DNS_RCODE_NOERROR,
                           aa = true,
                           qc = 1,
                           adc = 1,
                           questions = [#dns_query{name = ZoneName, class = ?DNS_CLASS_IN,
                                                   type = ?DNS_TYPE_AXFR}]},
    {ok, Recv} = case erldns_encoder:encode_message(Packet) of
                     {false, EncodedMessage} ->
                         send_tcp_message(BindIP, DestinationIP, EncodedMessage);
                     {true, EncodedMessage, Message} when is_record(Message, dns_message) ->
                         send_tcp_message(BindIP, DestinationIP, EncodedMessage);
                     {false, EncodedMessage, _TsigMac} ->
                         send_tcp_message(BindIP, DestinationIP, EncodedMessage);
                     {true, EncodedMessage, _TsigMac, _Message} ->
                         send_tcp_message(BindIP, DestinationIP, EncodedMessage)
                 end,
    %% Get new records from answer, delete old zone and replace it with the new zone
    NewRecords0 = dns:decode_message(Recv),
    NewRecords = NewRecords0#dns_message.answers,
    %% AFXR requests always have the authority at the beginning and end of the answer section.
    [Authority | RestOfRecords] = NewRecords,
    {ok, Zone} = erldns_zone_cache:get_zone_with_records(ZoneName),
    NewZone = erldns_zone_cache:build_zone(ZoneName, Zone#zone.allow_notify, Zone#zone.allow_transfer,
                                           Zone#zone.allow_update, Zone#zone.also_notify,
                                           Zone#zone.notify_source, Zone#zone.version, [Authority],
                                           RestOfRecords),
    ok = erldns_zone_cache:delete_zone(ZoneName),
    ok = erldns_zone_cache:put_zone(ZoneName, NewZone),
    exit(normal).

send_startup_zone_request(#zone{name = ZoneName} = Zone, BindIP, MasterIP) ->
    Packet =  #dns_message{id = dns:random_id(),
                           oc = ?DNS_OPCODE_QUERY,
                           rd = true,
                           ad = true,
                           rc = ?DNS_RCODE_NOERROR,
                           aa = true,
                           qc = 1,
                           adc = 1,
                           questions = [#dns_query{name = ZoneName, class = ?DNS_CLASS_IN,
                                                   type = ?DNS_TYPE_AXFR}]},
    {ok, Recv} = case erldns_encoder:encode_message(Packet) of
                     {false, EncodedMessage} ->
                         send_tcp_message(BindIP, MasterIP, EncodedMessage);
                     {true, EncodedMessage, Message} when is_record(Message, dns_message) ->
                         send_tcp_message(BindIP, MasterIP, EncodedMessage);
                     {false, EncodedMessage, _TsigMac} ->
                         send_tcp_message(BindIP, MasterIP, EncodedMessage);
                     {true, EncodedMessage, _TsigMac, _Message} ->
                         send_tcp_message(BindIP, MasterIP, EncodedMessage)
                 end,
    %% Get new records from answer, delete old zone and replace it with the new zone
    NewRecords0 = dns:decode_message(Recv),
    NewRecords = NewRecords0#dns_message.answers,
    %% AFXR requests always have the authority at the beginning and end of the answer section.
    [_Authority | RestOfRecords] = NewRecords,
    NewZone = erldns_zone_cache:build_zone(Zone#zone{records = RestOfRecords}),
    erldns_zone_cache:put_zone(ZoneName, NewZone).

%%%===================================================================
%%% Utility functions
%%%===================================================================
%% RFC 1996
%% 3.5. If TCP is used, both master and slave must continue to offer
%% name service during the transaction, even when the TCP transaction is
%% not making progress.  The NOTIFY request is sent once, and a
%% "timeout" is said to have occurred if no NOTIFY response is received
%% within a reasonable interval.
-spec send_tcp_message(inet:ip_address(), {inet:ip_address(), inet:port_number()}, binary()) ->
                              ok | {error, Reason :: term()}.
send_tcp_message(BindIP, DestinationIP, EncodedMessage) ->
    BinLength = byte_size(EncodedMessage),
    TcpEncodedMessage = <<BinLength:16, EncodedMessage/binary>>,
    send_recv(BindIP, DestinationIP, TcpEncodedMessage).

send_recv(BindIP, DestinationIP, TcpEncodedMessage) ->
    {ok, Socket} = gen_tcp:connect(DestinationIP, ?DNS_LISTEN_PORT, [binary, {active, false}, {ip, BindIP}]),
    ok = gen_tcp:send(Socket, TcpEncodedMessage),
    %% Extract the size header
    {ok, <<Length:16, Res0/binary>>} = gen_tcp:recv(Socket, 0),
    %% Only return data up to specified length
    <<Res:Length/binary, _/binary>> = Res0,
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

%% @doc Takes a list of dns_rrs and converts them to a list of dns_querys
-spec build_questions([dns:rr()]) -> dns:questions().
build_questions(DNSRRList) ->
    build_questions(DNSRRList, []).

build_questions([], Acc) ->
    %% Remove duplicate questions from the list.
    Set = sets:from_list(Acc),
    sets:to_list(Set);
build_questions([#dns_rr{name = Name, class = Class, type = Type}  | Tail], Acc) ->
    build_questions(Tail, [#dns_query{name = Name, class = Class,
                                      type = Type} | Acc]).

%% @doc Since erl-dns does not handle recursive queries, we need to do a query for every question.
%% annoying but this will have to do for now...
%% @end
-spec query_server_for_answers(inet:ip_address(), inet:ip_address(), dns:questions()) -> [dns:rr()].
query_server_for_answers(DestinationIP, BindIP, Questions) ->
    query_server_for_answers(DestinationIP, BindIP, Questions, []).

query_server_for_answers(_DestinationIP, _BindIP, [], Acc) ->
    Acc;
query_server_for_answers(DestinationIP, BindIP, [Question | Tail], Acc) ->
    Packet = #dns_message{id = dns:random_id(),
                          qr = false,
                          oc = ?DNS_OPCODE_QUERY,
                          aa = false,
                          tc = false,
                          rd = true,
                          ra = false,
                          ad = true,
                          cd = false,
                          rc = ?DNS_RCODE_NOERROR,
                          qc = 1,
                          adc = 1,
                          questions = [Question],
                          additional = [#dns_optrr{udp_payload_size = 4096, ext_rcode = ?DNS_ERCODE_NOERROR,
                                                   version = 0, dnssec = false, data = []}]},
    {ok, Recv} = case erldns_encoder:encode_message(Packet) of
                     {false, EncodedMessage} ->
                         send_tcp_message(BindIP, DestinationIP, EncodedMessage);
                     {true, EncodedMessage, Message} when is_record(Message, dns_message) ->
                         send_tcp_message(BindIP, DestinationIP, EncodedMessage);
                     {false, EncodedMessage, _TsigMac} ->
                         send_tcp_message(BindIP, DestinationIP, EncodedMessage);
                     {true, EncodedMessage, _TsigMac, _Message} ->
                         send_tcp_message(BindIP, DestinationIP, EncodedMessage)
                 end,
    DecodedMessage = dns:decode_message(Recv),
    if
        DecodedMessage#dns_message.answers =:= [] ->
            erldns_log:warning("Didn't receive answers for question: ~p", [Question])
    end,
    lists:flatten(query_server_for_answers(DestinationIP, BindIP, Tail, [DecodedMessage#dns_message.answers | Acc])).
