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

%% @doc Cowboy handler for the Metrics API endpoint /
-module(erldns_metrics_root_handler).

-export([init/3]).
-export([content_types_provided/2]).
-export([to_html/2, to_json/2, to_text/2]).

init(_Transport, _Req, []) ->
  {upgrade, protocol, cowboy_rest}.

content_types_provided(Req, State) ->
  {[
      {<<"text/html">>, to_html},
      {<<"text/plain">>, to_text},
      {<<"application/json">>, to_json}
    ], Req, State}.

to_html(Req, State) ->
  {<<"erldns metrics">>, Req, State}.

to_text(Req, State) ->
  {<<"erldns metrics">>, Req, State}.

to_json(Req, State) ->
  Body = jsx:encode([{<<"erldns">>, 
        [
          {<<"metrics">>, erldns_metrics:filtered_metrics()},
          {<<"stats">>, erldns_metrics:filtered_stats()},
          {<<"vm">>, erldns_metrics:filtered_vm()},
          {<<"ets">>, erldns_metrics:filtered_ets()}
        ]
      }]),
  {Body, Req, State}.
