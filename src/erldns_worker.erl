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

%% @doc Worker module that processes a single DNS packet.
-module(erldns_worker).

-include_lib("dns/include/dns.hrl").

-behaviour(gen_server).
-behaviour(poolboy_worker).

-export([start_link/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-record(state, {}).

-define(MAX_PACKET_SIZE, 512).
-define(REDIRECT_TO_LOOPBACK, false).
-define(LOOPBACK_DEST, {127, 0, 0, 10}).

start_link(Args) ->
  gen_server:start_link(?MODULE, Args, []).

init(_Args) ->
  {ok, #state{}}.

handle_call({tcp_query, Socket, Bin}, _From, State) ->
  {reply, handle_tcp_dns_query(Socket, Bin), State};
handle_call(_Request, _From, State) ->
  {reply, ok, State}.

handle_cast({udp_query, Socket, Host, Port, Bin}, State) ->
  handle_udp_dns_query(Socket, Host, Port, Bin),
  {noreply, State};
handle_cast(_Msg, State) ->
  {noreply, State}.
handle_info(_Info, State) ->
  {noreply, State}.
terminate(_Reason, _State) ->
  ok.
code_change(_OldVsn, State, _Extra) ->
  {ok, State}.

%% @doc Handle DNS query that comes in over TCP
-spec handle_tcp_dns_query(gen_tcp:socket(), iodata())  -> ok.
handle_tcp_dns_query(Socket, <<_Len:16, Bin/binary>>) ->
  {ok, {Address, _Port}} = inet:peername(Socket),
  erldns_events:notify({start_tcp, [{host, Address}]}),
  case Bin of
    <<>> -> ok;
    _ ->
      case dns:decode_message(Bin) of
        {truncated, _, _} ->
          lager:info("received truncated request from ~p", [Address]),
          ok;
        {trailing_garbage, DecodedMessage, _} ->
          handle_decoded_tcp_message(DecodedMessage, Socket, Address);
        {_Error, _, _} ->
          ok;
        DecodedMessage ->
          handle_decoded_tcp_message(DecodedMessage, Socket, Address)
      end
  end,
  erldns_events:notify({end_tcp, [{host, Address}]}),
  gen_tcp:close(Socket);
handle_tcp_dns_query(Socket, BadPacket) ->
  lager:error("Received bad packet ~p", BadPacket),
  gen_tcp:close(Socket).

handle_decoded_tcp_message(DecodedMessage, Socket, Address) ->
  erldns_events:notify({start_handle, tcp, [{host, Address}]}),
  Response = erldns_handler:handle(DecodedMessage, {tcp, Address}),
  erldns_events:notify({end_handle, tcp, [{host, Address}]}),
  case erldns_encoder:encode_message(Response) of
    {false, EncodedMessage} ->
      send_tcp_message(Socket, EncodedMessage);
    {true, EncodedMessage, Message} when is_record(Message, dns_message) ->
      send_tcp_message(Socket, EncodedMessage);
    {false, EncodedMessage, _TsigMac} ->
      send_tcp_message(Socket, EncodedMessage);
    {true, EncodedMessage, _TsigMac, _Message} ->
      send_tcp_message(Socket, EncodedMessage)
  end.

send_tcp_message(Socket, EncodedMessage) ->
  BinLength = byte_size(EncodedMessage),
  TcpEncodedMessage = <<BinLength:16, EncodedMessage/binary>>,
  gen_tcp:send(Socket, TcpEncodedMessage).


%% @doc Handle DNS query that comes in over UDP
-spec handle_udp_dns_query(gen_udp:socket(), gen_udp:ip(), inet:port_number(), binary()) -> ok.
handle_udp_dns_query(Socket, Host, Port, Bin) ->
  %lager:debug("handle_udp_dns_query(~p ~p ~p)", [Socket, Host, Port]),
  erldns_events:notify({start_udp, [{host, Host}]}),
  case dns:decode_message(Bin) of
    {trailing_garbage, DecodedMessage, _} ->
      handle_decoded_udp_message(DecodedMessage, Socket, Host, Port);
    {_Error, _, _} ->
      ok;
    DecodedMessage ->
      handle_decoded_udp_message(DecodedMessage, Socket, Host, Port)
  end,
  erldns_events:notify({end_udp, [{host, Host}]}),
  ok.

-spec handle_decoded_udp_message(dns:message(), gen_udp:socket(), gen_udp:ip(), inet:port_number()) ->
  ok | {error, not_owner | inet:posix()}.
handle_decoded_udp_message(DecodedMessage, Socket, Host, Port) ->
  Response = erldns_handler:handle(DecodedMessage, {udp, Host}),
  DestHost = case ?REDIRECT_TO_LOOPBACK of
    true -> ?LOOPBACK_DEST;
    _ -> Host
  end,

  case erldns_encoder:encode_message(Response, [{'max_size', max_payload_size(Response)}]) of
    {false, EncodedMessage} ->
      %lager:debug("Sending encoded response to ~p", [DestHost]),
      gen_udp:send(Socket, DestHost, Port, EncodedMessage);
    {true, EncodedMessage, Message} when is_record(Message, dns_message)->
      gen_udp:send(Socket, DestHost, Port, EncodedMessage);
    {false, EncodedMessage, _TsigMac} ->
      gen_udp:send(Socket, DestHost, Port, EncodedMessage);
    {true, EncodedMessage, _TsigMac, _Message} ->
      gen_udp:send(Socket, DestHost, Port, EncodedMessage)
  end.

%% Determine the max payload size by looking for additional
%% options passed by the client.
max_payload_size(Message) ->
  case Message#dns_message.additional of
    [Opt|_] when is_record(Opt, dns_optrr) ->
      case Opt#dns_optrr.udp_payload_size of
        [] -> ?MAX_PACKET_SIZE;
        _ -> Opt#dns_optrr.udp_payload_size
      end;
    _ -> ?MAX_PACKET_SIZE
  end.
