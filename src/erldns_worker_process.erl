%% Copyright (c) 2012-2020, DNSimple Corporation
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
-module(erldns_worker_process).

-include_lib("dns_erlang/include/dns.hrl").

-behaviour(gen_server).

-export([start_link/1]).
-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3
]).

-define(MIN_PACKET_SIZE, 512).
-define(MAX_PACKET_SIZE, 1232).
-define(REDIRECT_TO_LOOPBACK, false).
-define(LOOPBACK_DEST, {127, 0, 0, 10}).

-if(?REDIRECT_TO_LOOPBACK).

-define(DEST_HOST(_Host), ?LOOPBACK_DEST).

-else.

-define(DEST_HOST(Host), Host).

-endif.

-record(state, {}).

start_link(Args) ->
    gen_server:start_link(?MODULE, Args, []).

init(_Args) ->
    {ok, #state{}}.

% Process a TCP request. Does not truncate the response.
handle_call({process, DecodedMessage, Socket, {tcp, Address}, TS0}, _From, State) ->
    % Uncomment this and the function implementation to simulate a timeout when
    % querying www.example.com with the test zones
    % simulate_timeout(DecodedMessage),
    Response = erldns_handler:handle(DecodedMessage, {tcp, Address}),
    EncodedMessage = erldns_encoder:encode_message(Response),
    send_tcp_message(Socket, EncodedMessage),
    measure_time(DecodedMessage, tcp, TS0),
    {reply, ok, State};
% Process a UDP request. May truncate the response.
handle_call({process, DecodedMessage, Socket, Port, {udp, Host}, TS0}, _From, State) ->
    % Uncomment this and the function implementation to simulate a timeout when
    % querying www.example.com with the test zones
    % simulate_timeout(DecodedMessage),
    Response = erldns_handler:handle(DecodedMessage, {udp, Host}),
    DestHost = ?DEST_HOST(Host),

    Result = erldns_encoder:encode_message(Response, [{max_size, max_payload_size(Response)}]),
    case Result of
        {false, EncodedMessage} ->
            % ?LOG_DEBUG("Sending encoded response to ~p", [DestHost]),
            gen_udp:send(Socket, DestHost, Port, EncodedMessage);
        {true, EncodedMessage, Message} when is_record(Message, dns_message) ->
            gen_udp:send(Socket, DestHost, Port, EncodedMessage);
        {false, EncodedMessage, _TsigMac} ->
            gen_udp:send(Socket, DestHost, Port, EncodedMessage);
        {true, EncodedMessage, _TsigMac, _Message} ->
            gen_udp:send(Socket, DestHost, Port, EncodedMessage)
    end,
    measure_time(DecodedMessage, udp, TS0),
    {reply, ok, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% Internal private functions

send_tcp_message(Socket, EncodedMessage) ->
    BinLength = byte_size(EncodedMessage),
    TcpEncodedMessage = <<BinLength:16, EncodedMessage/binary>>,
    gen_tcp:send(Socket, TcpEncodedMessage).

measure_time(Message, Transport, TS0) ->
    TS1 = erlang:monotonic_time(),
    DnsSec = proplists:get_bool(dnssec, erldns_edns:get_opts(Message)),
    Labels = [Transport, DnsSec],
    prometheus_quantile_summary:observe(dns_request_duration_microseconds, Labels, TS1 - TS0).

%% Determine the max payload size by looking for additional
%% options passed by the client.
max_payload_size(Message) ->
    case Message#dns_message.additional of
        [#dns_optrr{udp_payload_size = Size} | _] ->
            case ?MIN_PACKET_SIZE =< Size andalso Size =< ?MAX_PACKET_SIZE of
                true -> Size;
                false -> ?MAX_PACKET_SIZE
            end;
        _ ->
            ?MIN_PACKET_SIZE
    end.

%simulate_timeout(DecodedMessage) ->
  %[Question] = DecodedMessage#dns_message.questions,
  %Name = Question#dns_query.name,
  %?LOG_INFO("qname: ~p", [Name]),
  %case Name of

    %<<"www.example.com">> ->
      %timer:sleep(3000);

    %_ ->
      %ok

  %end.
