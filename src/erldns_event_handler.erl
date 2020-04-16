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

%% @doc Application event handler implementation.
-module(erldns_event_handler).

-behavior(gen_event).

-export([
         init/1,
         handle_event/2,
         handle_call/2,
         handle_info/2,
         code_change/3,
         terminate/2
        ]).

-record(state, {servers_running = false}).

init(_Args) ->
  {ok, #state{}}.

handle_event({_M, start_servers}, State) ->
  case State#state.servers_running of
    false ->
      % Start up the UDP and TCP servers
      lager:info("Starting the UDP and TCP supervisor"),
      erldns_server_sup:start_link(),
      erldns_events:notify({?MODULE, servers_started}),
      {ok, State#state{servers_running = true}};
    _ ->
      erldns_events:notify({?MODULE, servers_already_started}),
      {ok, State}
  end;

handle_event({_M, end_udp, [{host, _Host}]}, State) ->
  folsom_metrics:notify({udp_request_meter, 1}),
  folsom_metrics:notify({udp_request_counter, {inc, 1}}),
  {ok, State};

handle_event({_M, end_tcp, [{host, _Host}]}, State) ->
  folsom_metrics:notify({tcp_request_meter, 1}),
  folsom_metrics:notify({tcp_request_counter, {inc, 1}}),
  {ok, State};

handle_event({_M, udp_error, Reason}, State) ->
  folsom_metrics:notify({udp_error_meter, 1}),
  folsom_metrics:notify({udp_error_history, Reason}),
  {ok, State};

handle_event({_M, tcp_error, Reason}, State) ->
  folsom_metrics:notify({tcp_error_meter, 1}),
  folsom_metrics:notify({tcp_error_history, Reason}),
  {ok, State};

handle_event({_M, dnssec_request, _Host, _Qname}, State) ->
  folsom_metrics:notify(dnssec_request_counter, {inc, 1}),
  folsom_metrics:notify(dnssec_request_meter, 1),
  {ok, State};

handle_event({M = erldns_handler, E = refused_response, Questions}, State) ->
  folsom_metrics:notify({refused_response_meter, 1}),
  folsom_metrics:notify({refused_response_counter, {inc, 1}}),
  lager:info("Refused response (module: ~p, event: ~p, questions: ~p)", [M, E, Questions]),
  {ok, State};

handle_event({M = erldns_handler, E = empty_response, Message}, State) ->
  folsom_metrics:notify({empty_response_meter, 1}),
  folsom_metrics:notify({empty_response_counter, {inc, 1}}),
  lager:info("Empty response (module: ~p, event: ~p, message: ~p)", [M, E, Message]),
  {ok, State};

handle_event({M = erldns_handler, E = error, {Exception, Reason, Message}}, State) ->
  folsom_metrics:notify({erldns_handler_error_counter, {inc, 1}}),
  folsom_metrics:notify({erldns_handler_error_meter, 1}),
  lager:error("Error answering request (module: ~p, event: ~p, exception: ~p, reason: ~p, message: ~p)", [M, E, Exception, Reason, Message]),
  {ok, State};

handle_event({M = erldns_zone_loader, E = read_file_error, Reason}, State) ->
  lager:error("Failed to load zones (module: ~p, event: ~p, reason: ~p)", [M, E, Reason]),
  {ok, State};

handle_event({M = erldns_zone_loader, E = put_zone_error, {JsonZone, Reason}}, State) ->
  lager:error("Failed to load zones (module: ~p, event: ~p, reason: ~p, json: ~p)", [M, E, Reason, JsonZone]),
  {ok, State};

handle_event({M = erldns_zone_parser, E = error, {Name, Type, Data, Reason}}, State) ->
  lager:error("Error parsing record (module: ~p, event: ~p, name: ~p, type: ~p, data: ~p, reason: ~p)", [M, E, Name, Type, Data, Reason]),
  {ok, State};

handle_event({M = erldns_zone_parser, E = error, {Name, Type, Data, Exception, Reason}}, State) ->
  lager:error("Error parsing record (module: ~p, event: ~p, name: ~p, type: ~p, data: ~p, exception: ~p, reason: ~p)", [M, E, Name, Type, Data, Exception, Reason]),
  {ok, State};

handle_event({M = erldns_zone_parser, E = unsupported_record, Data}, State) ->
  lager:warning("Unsupported record (module: ~p, event: ~p, data: ~p)", [M, E, Data]),
  {ok, State};

handle_event({M = erldns_decoder, E = decode_message_error, {Exception, Reason, Bin}}, State) ->
  lager:error("Error decoding message (module: ~p, event: ~p, data: ~p, exception: ~p, reason: ~p)", [M, E, Bin, Exception, Reason]),
  {ok, State};

handle_event({M = eldns_encoder, E = encode_message_error, {Exception, Reason, Response}}, State) ->
  lager:error("Error encoding message (module: ~p, event: ~p, response: ~p, exception: ~p, reason: ~p)", [M, E, Response, Exception, Reason]),
  {ok, State};

handle_event({M = erldns_encoder, E = encode_message_error, {Exception, Reason, Response, Opts}}, State) ->
  lager:error("Error encoding with opts (module: ~p, event: ~p, response: ~p, opts: ~p, exception: ~p, reason: ~p)", [M, E, Response, Opts,Exception, Reason]),
  {ok, State};

handle_event({M = erldns_worker, E = handle_tcp_query_error, {Error}}, State) ->
  lager:error("Error handling TCP query (module: ~p, event: ~p, error: ~p)", [M, E, Error]),
  {ok, State};

handle_event({M = erldns_worker, E = handle_udp_query_error, {Error}}, State) ->
  lager:error("Error handling UDP query (module: ~p, event: ~p, error: ~p)", [M, E, Error]),
  {ok, State};

handle_event({M = erldns_worker, E = decode_message_error, {Error, Message}}, State) ->
  lager:error("Error decoding message (module: ~p, event: ~p, error: ~p, message: ~p)", [M, E, Error, Message]),
  {ok, State};

handle_event({M = erldns_worker, E = decode_message_trailing_garbage, {Message, Garbage}}, State) ->
  lager:info("Decoded message included trailing garbage (module: ~p, event: ~p, message: ~p, garbage: ~p)", [M, E, Message, Garbage]),
  {ok, State};

handle_event({M = erldns_worker, E = process_crashed, {Protocol, Error, Reason, DecodedMessage}}, State) ->
  lager:error("Worker process crashed (module: ~p, event: ~p, protocol: ~p, error: ~p, reason: ~p, message: ~p)", [M, E, Protocol, Error, Reason, DecodedMessage]),
  {ok, State};

handle_event({M = erldns_worker, E = bad_packet, {Protocol, BadPacket}}, State) ->
  lager:error("Received bad packet (module: ~p, event: ~p, protocol: ~p, packet: ~p)", [M, E, Protocol, BadPacket]),
  {ok, State};

handle_event({M = erldns_worker, E = timeout, {Protocol, Message}}, State) ->
  lager:info("Worker timeout (module: ~p, event: ~p, protocol: ~p, message: ~p)", [M, E, Protocol, Message]),
  folsom_metrics:notify({worker_timeout_counter, {inc, 1}}),
  folsom_metrics:notify({worker_timeout_meter, 1}),
  {ok, State};

handle_event({M = erldns_worker, E = restart_failed, Error}, State) ->
  lager:error("Restart failed (module: ~p, event: ~p, error: ~p)", [M, E, Error]),
  {ok, State};



handle_event(_Event, State) ->
  {ok, State}.

handle_call(_Message, State) ->
  {ok, ok, State}.

handle_info(_Message, State) ->
  {ok, State}.

code_change(_OldVsn, State, _Extra) ->
  {ok, State}.

terminate(_Reason, _State) ->
  ok.
