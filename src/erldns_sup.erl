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

%% @doc Application supervisor. Supervises everything except the UDP and TCP
%% listeners and the zone checker.
-module(erldns_sup).
-behavior(supervisor).

% API
-export([start_link/0]).

-export([
         gc/0,
         gc_registered/0,
         gc_registered/1
        ]).

% Supervisor hooks
-export([init/1]).

-define(SUPERVISOR, ?MODULE).

%% Helper macro for declaring children of supervisor
-define(CHILD(I, Type, Args), {I, {I, start_link, Args}, permanent, 5000, Type, [I]}).

%% Public API
-spec start_link() -> any().
start_link() ->
  supervisor:start_link({local, ?SUPERVISOR}, ?MODULE, []).

%% @doc Garbage collect all processes.
-spec gc() -> integer().
gc() ->
  length(
    lists:map(
      fun(Pid) ->
          garbage_collect(Pid)
      end,
      processes())
   ).

%% @doc Garbage collect all registered processes.
-spec gc_registered() -> integer().
gc_registered() ->
  length(
    lists:map(
      fun(ProcessName) ->
          gc_registered(ProcessName)
      end,
      registered())
   ).

%% @doc Garbage collect a named process.
-spec gc_registered(atom()) -> ok.
gc_registered(ProcessName) ->
  Pid = whereis(ProcessName),
  garbage_collect(Pid),
  ok.


%% Callbacks
init(_Args) ->
  SysProcs = [
              ?CHILD(erldns_events, worker, []),
              ?CHILD(erldns_zone_cache, worker, []),
              ?CHILD(erldns_zone_parser, worker, []),
              ?CHILD(erldns_zone_encoder, worker, []),
              ?CHILD(erldns_packet_cache, worker, []),
              ?CHILD(erldns_query_throttle, worker, []),
              ?CHILD(erldns_handler, worker, []),
              ?CHILD(sample_custom_handler, worker, [])
             ],

  {ok, {{one_for_one, 20, 10}, SysProcs}}.
