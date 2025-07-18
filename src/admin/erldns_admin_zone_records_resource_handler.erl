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

-module(erldns_admin_zone_records_resource_handler).
-moduledoc false.
%% Cowbow handler that handles Admin API requests to /zones/:name.

-export([init/2]).
-export([content_types_provided/2, is_authorized/2, resource_exists/2, allowed_methods/2]).
-export([to_html/2, to_json/2, to_text/2]).

-behaviour(cowboy_rest).

-include_lib("kernel/include/logger.hrl").

-doc false.
-spec init(cowboy_req:req(), erldns_admin:handler_state()) ->
    {cowboy_rest, cowboy_req:req(), erldns_admin:handler_state()}.
init(Req, State) ->
    {cowboy_rest, Req, State}.

-doc "Only GET method is allowed".
-spec allowed_methods(cowboy_req:req(), erldns_admin:handler_state()) ->
    {[binary()], cowboy_req:req(), erldns_admin:handler_state()}.
allowed_methods(Req, State) ->
    {[<<"GET">>], Req, State}.

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
    {erldns_zone_cache:is_in_any_zone(Name), Req, State}.

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
    ZoneName = cowboy_req:binding(zone_name, Req),
    RecordName = cowboy_req:binding(record_name, Req, <<>>),
    Params = cowboy_req:parse_qs(Req),
    Type = lists:keyfind(<<"type">>, 1, Params),
    ?LOG_DEBUG(
        #{what => get_zone_resource_call, zone => ZoneName, record => RecordName, type => Type},
        #{domain => [erldns, admin]}
    ),
    case {RecordName, Type} of
        {<<>>, false} ->
            Opts = #{mode => zone_records_to_json},
            return_answer(ZoneName, Opts, Req, State);
        {_, false} ->
            Opts = #{mode => {zone_records_to_json, RecordName}},
            return_answer(ZoneName, Opts, Req, State);
        {_, {_, RecordType}} ->
            Opts = #{mode => {zone_records_to_json, RecordName, RecordType}},
            return_answer(ZoneName, Opts, Req, State)
    end.

return_answer(ZoneName, Opts, Req, State) ->
    case erldns_zone_cache:lookup_zone(ZoneName) of
        zone_not_found ->
            ?LOG_ERROR(#{what => get_zone_records_error, error => zone_not_found}, #{
                domain => [erldns, admin]
            }),
            Resp = "Error getting zone: zone not found",
            {stop, cowboy_req:reply(400, #{}, Resp, Req), State};
        Zone ->
            Json = erldns_zone_codec:encode(Zone, Opts),
            Response = iolist_to_binary(json:encode(Json)),
            {Response, Req, State}
    end.
