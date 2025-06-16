-module(erldns_admin_root_handler).
-moduledoc false.
-include_lib("kernel/include/logger.hrl").

-export([init/2]).
-export([
    content_types_provided/2,
    is_authorized/2,
    allowed_methods/2,
    delete_resource/2
]).
-export([to_html/2, to_json/2, to_text/2]).

-behaviour(cowboy_rest).

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

-doc """
Delete query queues
""".
-spec delete_resource(cowboy_req:req(), erldns_admin:handler_state()) ->
    {boolean(), cowboy_req:req(), erldns_admin:handler_state()}.
delete_resource(Req, State) ->
    ?LOG_WARNING(#{what => resetting_listener_queues}),
    {erldns_listeners:reset_queues(), Req, State}.

-doc "Return information about the zones in the cache.".
-spec to_json(cowboy_req:req(), erldns_admin:handler_state()) ->
    {cowboy_req:resp_body(), cowboy_req:req(), erldns_admin:handler_state()}.
to_json(Req, State) ->
    ZoneNamesAndVersionsForJson = lists:map(
        fun({Name, Version}) ->
            #{<<"name">> => Name, <<"version">> => Version}
        end,
        erldns_zone_cache:zone_names_and_versions()
    ),
    Body = json:encode(#{
        <<"erldns">> => #{
            <<"zones">> => #{
                <<"count">> => length(ZoneNamesAndVersionsForJson),
                <<"versions">> => ZoneNamesAndVersionsForJson
            }
        }
    }),
    {Body, Req, State}.
