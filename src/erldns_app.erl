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

%% @doc The erldns OTP application.
-module(erldns_app).
-behavior(application).

% Application hooks
-export([start/2, start_phase/3, stop/1]).

start(_Type, _Args) ->
  lager:debug("Starting erldns application"),
  setup_metrics(),
  erldns_sup:start_link().

start_phase(post_start, _StartType, _PhaseArgs) ->
  lager:debug("Post start phase for erldns application"),
  erldns_events:add_handler(erldns_event_handler),

  lager:debug("Loading custom zone parsers"),
  case application:get_env(erldns, custom_zone_parsers) of
    {ok, Parsers} -> erldns_zone_parser:register_parsers(Parsers);
    _ -> ok
  end,

  lager:debug("Loading custom zone encoders"),
  case application:get_env(erldns, custom_zone_encoders) of
    {ok, Encoders} -> erldns_zone_encoder:register_encoders(Encoders);
    _ -> ok
  end,

  lager:info("Loading zones from local file"),
  erldns_zone_loader:load_zones(),

  lager:info("Notifying servers to start"),
  erldns_events:notify(start_servers),

  ok.

stop(_State) ->
  lager:info("Stop erldns application"),
  ok.

setup_metrics() ->
  folsom_metrics:new_counter(udp_request_counter),
  folsom_metrics:new_counter(tcp_request_counter),
  folsom_metrics:new_meter(udp_request_meter),
  folsom_metrics:new_meter(tcp_request_meter),

  folsom_metrics:new_meter(udp_error_meter),
  folsom_metrics:new_meter(tcp_error_meter),
  folsom_metrics:new_history(udp_error_history),
  folsom_metrics:new_history(tcp_error_history),

  folsom_metrics:new_meter(refused_response_meter),
  folsom_metrics:new_counter(refused_response_counter),

  folsom_metrics:new_meter(empty_response_meter),
  folsom_metrics:new_counter(empty_response_counter),

  folsom_metrics:new_histogram(udp_handoff_histogram),
  folsom_metrics:new_histogram(tcp_handoff_histogram),

  folsom_metrics:new_counter(request_throttled_counter),
  folsom_metrics:new_meter(request_throttled_meter),
  folsom_metrics:new_histogram(request_handled_histogram),

  folsom_metrics:new_counter(packet_dropped_empty_queue_counter),
  folsom_metrics:new_meter(packet_dropped_empty_queue_meter),

  folsom_metrics:new_counter(worker_timeout_counter),
  folsom_metrics:new_meter(worker_timeout_meter),

  folsom_metrics:new_meter(cache_hit_meter),
  folsom_metrics:new_meter(cache_expired_meter),
  folsom_metrics:new_meter(cache_miss_meter),

  folsom_metrics:new_counter(dnssec_request_counter),
  folsom_metrics:new_meter(dnssec_request_meter).
