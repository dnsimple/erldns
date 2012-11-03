-module(erldns_worker).

-include("dns_records.hrl").

-behaviour(gen_server).
-behaviour(poolboy_worker).

-export([start_link/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-record(state, {}).

-define(MAX_PACKET_SIZE, 512).

start_link(Args) ->
  gen_server:start_link(?MODULE, Args, []).

init(_Args) ->
  {ok, #state{}}.

handle_call({tcp_query, Socket, Bin}, _From, State) ->
  {reply, handle_tcp_dns_query(Socket, Bin), State};
handle_call({udp_query, Socket, Host, Port, Bin}, _From, State) ->
  {reply, handle_udp_dns_query(Socket, Host, Port, Bin), State};
handle_call(_Request, _From, State) ->
  {reply, ok, State}.
handle_cast(_Msg, State) ->
  {noreply, State}.
handle_info(_Info, State) ->
  {noreply, State}.
terminate(_Reason, _State) ->
  ok.
code_change(_OldVsn, State, _Extra) ->
  {ok, State}.

  %% Handle DNS query that comes in over TCP
handle_tcp_dns_query(Socket, Packet) ->
  lager:debug("handle_tcp_dns_query(~p)", [Socket]),
  %% TODO: measure 
  <<_Len:16, Bin/binary>> = Packet,
  {ok, {Address, _Port}} = inet:peername(Socket),
  case Bin of
    <<>> -> ok;
    _ ->
      case dns:decode_message(Bin) of
        {truncated, _} -> lager:info("received bad request from ~p", [Address]);
        DecodedMessage ->
          Response = erldns_handler:handle(DecodedMessage, Address),
          BinReply = erldns_encoder:encode_message(Response),
          BinLength = byte_size(BinReply),
          TcpBinReply = <<BinLength:16, BinReply/binary>>,
          gen_tcp:send(Socket, TcpBinReply)
      end
  end,
  gen_tcp:close(Socket).

%% Handle DNS query that comes in over UDP
handle_udp_dns_query(Socket, Host, Port, Bin) ->
  lager:debug("handle_udp_dns_query(~p ~p ~p)", [Socket, Host, Port]),
  %% TODO: measure
  case dns:decode_message(Bin) of
    {truncated, _} -> lager:debug("received bad request from ~p", [Host]);
    {formerr, _, _} -> lager:debug("formerr bad request from ~p", [Host]);
    DecodedMessage ->
      Response = erldns_handler:handle(DecodedMessage, Host),
      EncodedMessage = erldns_encoder:encode_message(Response),
      BinLength = byte_size(EncodedMessage),
      gen_udp:send(Socket, Host, Port, optionally_truncate(Response, EncodedMessage, BinLength))
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

%% Truncate the message and encode if necessary.
optionally_truncate(Message, EncodedMessage, BinLength) ->
  case BinLength > max_payload_size(Message) of
    true -> dns:encode_message(truncate(Message));
    false -> EncodedMessage
  end.

%% Truncate the message for UDP packet limitations (at least that
%% is what it may eventually do. Right now it simply sets the
%% tc bit to indicate the message was truncated.
truncate(Message) ->
  lager:debug("Message was truncated: ~p", [Message]),
  Message#dns_message{tc = true}.
