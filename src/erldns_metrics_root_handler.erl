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
          {<<"metrics">>, erldns_metrics:metrics()},
          {<<"stats">>, erldns_metrics:filtered_stats()}
        ]
      }]),
  {Body, Req, State}.
