%% Copyright (c) DNSimple Corporation
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

-export([init/2]).
-export([content_types_provided/2]).
-export([to_html/2, to_json/2, to_text/2]).

-behaviour(cowboy_rest).

-doc false.
-spec init(cowboy_req:req(), erldns_admin:handler_state()) ->
    {cowboy_rest, cowboy_req:req(), erldns_admin:handler_state()}.
init(Req, State) ->
    {cowboy_rest, Req, State}.

-doc false.
-spec content_types_provided(cowboy_req:req(), erldns_admin:handler_state()) ->
    {[{{binary(), binary(), '*'}, atom()}], cowboy_req:req(), erldns_admin:handler_state()}.
content_types_provided(Req, State) ->
    {
        [
            {{<<"text">>, <<"html">>, '*'}, to_html},
            {{<<"text">>, <<"plain">>, '*'}, to_text},
            {{<<"application">>, <<"json">>, '*'}, to_json}
        ],
        Req,
        State
    }.

-doc false.
-spec to_html(cowboy_req:req(), erldns_admin:handler_state()) ->
    {cowboy_req:resp_body(), cowboy_req:req(), erldns_admin:handler_state()}.
to_html(Req, State) ->
    {<<"erldns metrics">>, Req, State}.

-doc false.
-spec to_text(cowboy_req:req(), erldns_admin:handler_state()) ->
    {cowboy_req:resp_body(), cowboy_req:req(), erldns_admin:handler_state()}.
to_text(Req, State) ->
    {<<"erldns metrics">>, Req, State}.

-doc "Return information about the zones in the cache.".
-spec to_json(cowboy_req:req(), erldns_admin:handler_state()) ->
    {cowboy_req:resp_body(), cowboy_req:req(), erldns_admin:handler_state()}.
to_json(Req, State) ->
    Metrics = [
        {<<"erldns">>, [
            {<<"metrics">>, erldns_metrics:filtered_metrics()},
            {<<"stats">>, erldns_metrics:filtered_stats()},
            {<<"vm">>, erldns_metrics:filtered_vm()},
            {<<"ets">>, erldns_metrics:filtered_ets()},
            {<<"processes">>, erldns_metrics:filtered_process_metrics()}
        ]}
    ],
    Body = iolist_to_binary(json:encode(Metrics, fun encode_to_json/2)),
    {Body, Req, State}.

encode_to_json([{_, _} | _] = Value, Encode) ->
    json:encode_key_value_list(Value, Encode);
encode_to_json(Value, Encode) ->
    json:encode_value(Value, Encode).
