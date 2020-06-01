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

-include_lib("kernel/include/logger.hrl").

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
      ?LOG_INFO(#{
	 log => event, in => start_servers, 
	 text => "Starting the UDP and TCP supervisor"
	}),
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

handle_event({M = erldns_handler, E = bad_message, {Message, Host}}, State) ->
  ?LOG_ERROR(#{
     log => event, in => M, what => E, 
     message => Message, host => Host,
     text => "Received a bad message"
    }),
  {ok, State};

handle_event({M = erldns_handler, E = refused_response, Questions}, State) ->
  folsom_metrics:notify({refused_response_meter, 1}),
  folsom_metrics:notify({refused_response_counter, {inc, 1}}),
  ?LOG_INFO(#{
     log => event, in => M, what => E, 
     questions => Questions, text => "Refused response"
    }),
  {ok, State};

handle_event({M = erldns_handler, E = empty_response, Message}, State) ->
  folsom_metrics:notify({empty_response_meter, 1}),
  folsom_metrics:notify({empty_response_counter, {inc, 1}}),
  ?LOG_INFO(#{
     log => event, in => M, what => E, 
     message => Message, text => "Empty response"
    }),
  {ok, State};

handle_event({M = erldns_handler, E = resolve_error, {Exception, Reason, Message, Stacktrace}}, State) ->
  folsom_metrics:notify({erldns_handler_error_counter, {inc, 1}}),
  folsom_metrics:notify({erldns_handler_error_meter, 1}),
  ?LOG_ERROR(#{
     log => event, in => M, what => E, 
     result => error, reason => Reason, 
     details => Exception, message => Message,
     stacktrace => Stacktrace,
     text => "Error answering request"
    }),
  {ok, State};

handle_event({M = erldns_zone_encoder, E = unsupported_rrdata_type, Data}, State) ->
  ?LOG_ERROR(#{
     log => event, in => M, what => E, 
     data => Data, 
     text => "Unable to encode rrdata"
    }),
  {ok, State};

handle_event({M = erldns_zone_loader, E = read_file_error, Reason}, State) ->
  ?LOG_ERROR(#{
     log => event, in => M, what => E, 
     result => error, reason => Reason,
     text => "Failed to load zones"
    }),
  {ok, State};

handle_event({M = erldns_zone_loader, E = put_zone_error, {JsonZone, Reason}}, State) ->
  ?LOG_ERROR(#{
     log => event, in => M, what => E, 
     result => error, reason => Reason,
     json => JsonZone,
     text => "Failed to load zones"
    }),
  {ok, State};

handle_event({M = erldns_zone_parser, E = error, {Name, Type, Data, Reason}}, State) ->
  ?LOG_ERROR(#{
     log => event, in => M, what => E, 
     result => error, reason => Reason,
     name => Name, type => Type,
     data => Data, text => "Error parsing record"
    }),
  {ok, State};

handle_event({M = erldns_zone_parser, E = error, {Name, Type, Data, Exception, Reason}}, State) ->
  ?LOG_ERROR(#{
     log => event, in => M, what => E, 
     result => error, reason => Reason,
     details => Exception,
     name => Name, type => Type,
     data => Data, text => "Error parsing record"
    }),
  {ok, State};

handle_event({M = erldns_zone_parser, E = unsupported_record, Data}, State) ->
  ?LOG_WARNING(#{
     log => event, in => M, what => E, 
     data => Data, text => "Unsupported record"
    }),
  {ok, State};

handle_event({M = erldns_decoder, E = decode_message_error, {Exception, Reason, Bin}}, State) ->
  ?LOG_ERROR(#{
     log => event, in => M, what => E, 
     result => error, reason => Reason,
     details => Exception,
     data => Bin, text => "Error decoding message"
    }),
  {ok, State};

handle_event({M = eldns_encoder, E = encode_message_error, {Exception, Reason, Response}}, State) ->
  ?LOG_ERROR(#{
     log => event, in => M, what => E, 
     result => error, reason => Reason,
     details => Exception,
     response => Response,
     text => "Error encoding message"
    }),
  {ok, State};

handle_event({M = erldns_encoder, E = encode_message_error, {Exception, Reason, Response, Opts}}, State) ->
  ?LOG_ERROR(#{
     log => event, in => M, what => E, 
     result => error, reason => Reason,
     details => Exception,
     response => Response,
     data => Opts,
     text => "Error encoding message wuth opts"
    }),
  {ok, State};

handle_event({M = erldns_storage, E = failed_zones_load, Reason}, State) ->
  ?LOG_ERROR(#{
     log => event, in => M, what => E, 
     result => error, reason => Reason,
     text => "Failed to load zones"
    }),
  {ok, State};

handle_event({M = erldns_worker, E = handle_tcp_query_error, {Error}}, State) ->
  ?LOG_ERROR(#{
     log => event, in => M, what => E, 
     result => error, details => Error,
     text => "Error handling TCP query"
    }),
  {ok, State};

handle_event({M = erldns_worker, E = handle_udp_query_error, {Error}}, State) ->
  ?LOG_ERROR(#{
     log => event, in => M, what => E, 
     result => error, details => Error,
     text => "Error handling UDP query"
    }),
  {ok, State};

handle_event({M = erldns_worker, E = decode_message_error, {Error, Message}}, State) ->
  ?LOG_ERROR(#{
     log => event, in => M, what => E, 
     result => error, details => Error,
     data => Message,
     text => "Error decoding message"
    }),
  {ok, State};

handle_event({M = erldns_worker, E = decode_message_trailing_garbage, {Message, Garbage}}, State) ->
  ?LOG_INFO(#{
     log => event, in => M, what => E, 
     message => Message, data => Garbage,
     text => "Decoded message included trailing garbage"
    }),
  {ok, State};

handle_event({M = erldns_worker, E = process_crashed, {Protocol, Error, Reason, DecodedMessage}}, State) ->
  ?LOG_ERROR(#{
     log => event, in => M, what => E, 
     result => error, details => Error,
     reason => Reason,
     protocol => Protocol,
     data => DecodedMessage,
     text => "Worker process crashed"
    }),
  {ok, State};

handle_event({M = erldns_worker, E = bad_packet, {Protocol, BadPacket}}, State) ->
  ?LOG_ERROR(#{
     log => event, in => M, what => E, 
     result => error,
     protocol => Protocol,
     data => BadPacket,
     text => "Received bad packet"
    }),
  {ok, State};

handle_event({M = erldns_worker, E = timeout, {Protocol, Message}}, State) ->
  ?LOG_INFO(#{
     log => event, in => M, what => E, 
     message => Message, protocol => Protocol,
     text => "Worker timeout"
    }),
  folsom_metrics:notify({worker_timeout_counter, {inc, 1}}),
  folsom_metrics:notify({worker_timeout_meter, 1}),
  {ok, State};

handle_event({M = erldns_worker, E = restart_failed, Error}, State) ->
  ?LOG_ERROR(#{
     log => event, in => M, what => E, 
     result => error, details => Error,
     text => "Restart failed"
    }),
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
