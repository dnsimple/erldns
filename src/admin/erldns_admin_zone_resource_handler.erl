%% Copyright (c) 2012-2019, DNSimple Corporation
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

-module(erldns_admin_zone_resource_handler).
-moduledoc "Cowbow handler that handles Admin API requests to /zones/:name".

-export([init/2]).
-export([
    content_types_provided/2,
    is_authorized/2,
    resource_exists/2,
    allowed_methods/2,
    delete_resource/2
]).
-export([to_html/2, to_json/2, to_text/2]).

-behaviour(cowboy_rest).

-include_lib("kernel/include/logger.hrl").

-doc false.
-spec init(cowboy_req:req(), erldns_admin:handler_state()) ->
    {cowboy_rest, cowboy_req:req(), erldns_admin:handler_state()}.
init(Req, State) ->
    {cowboy_rest, Req, State}.

-doc "Only GET and DELETE methods are allowed".
-spec allowed_methods(cowboy_req:req(), erldns_admin:handler_state()) ->
    {[binary()], cowboy_req:req(), erldns_admin:handler_state()}.
allowed_methods(Req, State) ->
    {[<<"GET">>, <<"DELETE">>], Req, State}.

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
-spec is_authorized(cowboy_req:req(), erldns_admin:handler_state()) ->
    {true | {false, iodata()}, cowboy_req:req(), erldns_admin:handler_state()}
    | {stop, cowboy_req:req(), erldns_admin:handler_state()}.
is_authorized(Req, State) ->
    erldns_admin:is_authorized(Req, State).

-doc "Verify if a zone is cached".
-spec resource_exists(cowboy_req:req(), erldns_admin:handler_state()) ->
    {boolean(), cowboy_req:req(), erldns_admin:handler_state()}.
resource_exists(Req, State) ->
    Name = cowboy_req:binding(zone_name, Req),
    {erldns_zone_cache:in_zone(Name), Req, State}.

-doc "Delete a zone from cache".
-spec delete_resource(cowboy_req:req(), erldns_admin:handler_state()) ->
    {boolean(), cowboy_req:req(), erldns_admin:handler_state()}.
delete_resource(Req, State) ->
    Name = cowboy_req:binding(zone_name, Req),
    ?LOG_DEBUG(#{what => received_delete_resource, resource => Name}),
    erldns_zone_cache:delete_zone(Name),
    {true, Req, State}.

-doc false.
-spec to_html(cowboy_req:req(), erldns_admin:handler_state()) ->
    {cowboy_req:resp_body(), cowboy_req:req(), erldns_admin:handler_state()}.
to_html(Req, State) ->
    {<<"erldns admin">>, Req, State}.

-doc false.
-spec to_text(cowboy_req:req(), erldns_admin:handler_state()) ->
    {cowboy_req:resp_body(), cowboy_req:req(), erldns_admin:handler_state()}.
to_text(Req, State) ->
    {<<"erldns admin">>, Req, State}.

-doc "Return information about a given zone in cache".
-spec to_json(cowboy_req:req(), erldns_admin:handler_state()) ->
    {stop | cowboy_req:resp_body(), cowboy_req:req(), erldns_admin:handler_state()}.
to_json(Req, State) ->
    Name = cowboy_req:binding(zone_name, Req),
    Params = cowboy_req:parse_qs(Req),
    ?LOG_DEBUG(#{what => received_get, resource => Name, params => Params}),
    case erldns_zone_cache:get_zone(Name) of
        {error, Reason} ->
            ?LOG_ERROR(#{what => get_zone_error, error => Reason}),
            Resp = io_lib:format("Error getting zone: ~p", [Reason]),
            {stop, cowboy_req:reply(400, #{}, Resp, Req), State};
        {ok, Zone} ->
            Body = get_body(Req, State, Zone, lists:keymember(<<"metaonly">>, 1, Params)),
            {Body, Req, State}
    end.

get_body(Req, State, Zone, false) ->
    {erldns_zone_encoder:zone_to_json(Zone), Req, State};
get_body(Req, State, Zone, true) ->
    {erldns_zone_encoder:zone_meta_to_json(Zone), Req, State}.
