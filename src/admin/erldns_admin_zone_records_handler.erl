-module(erldns_admin_zone_records_handler).
-moduledoc """
Support for the erldns Admin API root resource at path `/zones/:zonename/records[/:record_name]`.

The following is implemented:
- `GET`: Returns information about records in a given zone cached in erldns.
    The response JSON body looks like the following:
    ```json
    [
        {
            "name": "www.example.com.",
            "type": "CNAME",
            "ttl": 120,
            "content": "example.com."
        },
        {
            "name": "mail.example.com.",
            "type": "A",
            "ttl": 300,
            "content": "
    ```
""".

-export([
    init/2,
    content_types_provided/2,
    resource_exists/2,
    allowed_methods/2
]).
-export([to_html/2, to_text/2, to_json/2]).

-behaviour(cowboy_rest).

-include_lib("kernel/include/logger.hrl").

-define(LOG_METADATA, #{domain => [erldns, admin]}).

-doc false.
-spec init(cowboy_req:req(), dynamic()) ->
    {cowboy_rest, cowboy_req:req(), dynamic()}.
init(Req, State) ->
    {cowboy_rest, Req, State}.

-doc false.
-spec allowed_methods(cowboy_req:req(), dynamic()) ->
    {[binary()], cowboy_req:req(), dynamic()}.
allowed_methods(Req, State) ->
    {[~"GET"], Req, State}.

-doc false.
-spec content_types_provided(cowboy_req:req(), dynamic()) ->
    {[{{binary(), binary(), '*'}, atom()}], cowboy_req:req(), dynamic()}.
content_types_provided(Req, State) ->
    {
        [
            {{~"application", ~"json", '*'}, to_json},
            {{~"text", ~"html", '*'}, to_html},
            {{~"text", ~"plain", '*'}, to_text}
        ],
        Req,
        State
    }.

-doc false.
-spec resource_exists(cowboy_req:req(), dynamic()) ->
    {boolean(), cowboy_req:req(), dynamic()}.
resource_exists(Req, State) ->
    Name = cowboy_req:binding(zonename, Req),
    {erldns_zone_cache:is_in_any_zone(Name), Req, State}.

-doc false.
-spec to_html(cowboy_req:req(), dynamic()) ->
    {cowboy_req:resp_body(), cowboy_req:req(), dynamic()}.
to_html(Req, State) ->
    {~"erldns admin", Req, State}.

-doc false.
-spec to_text(cowboy_req:req(), dynamic()) ->
    {cowboy_req:resp_body(), cowboy_req:req(), dynamic()}.
to_text(Req, State) ->
    {~"erldns admin", Req, State}.

-doc false.
-spec to_json(cowboy_req:req(), dynamic()) ->
    {stop | cowboy_req:resp_body(), cowboy_req:req(), dynamic()}.
to_json(Req, State) ->
    ZoneName = cowboy_req:binding(zonename, Req),
    RecordName = cowboy_req:binding(record_name, Req),
    Type = lists:keyfind(~"type", 1, cowboy_req:parse_qs(Req)),
    ?LOG_DEBUG(
        #{what => get_zone_resource_call, zone => ZoneName, record => RecordName, type => Type},
        ?LOG_METADATA
    ),
    case {RecordName, Type} of
        {undefined, false} ->
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
            ?LOG_ERROR(#{what => get_zone_records_error, error => zone_not_found}, ?LOG_METADATA),
            Resp = "Error getting zone: zone not found",
            {stop, cowboy_req:reply(400, #{}, Resp, Req), State};
        Zone ->
            Json = erldns_zone_codec:encode(Zone, Opts),
            Response = json:encode(Json),
            {Response, Req, State}
    end.
