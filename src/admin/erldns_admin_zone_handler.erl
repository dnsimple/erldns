-module(erldns_admin_zone_handler).
-moduledoc """
Support for the erldns Admin API root resource at path `/zones/:name`.

The following is implemented:
- `DELETE`: Deletes a zone from cache.
- `GET`: Returns information about records in a given zone cached in erldns.
    Acceps an optional query parameter `metaonly`, that takes a boolean: if set to `true`
    only zone metadata is returned, without the actual `"records"`.

    The response JSON body looks like the following:
    ```json
    {
      "erldns": {
        "zone": {
          "name": "example.com",
          "version": "v1.2.3",
          "records_count": 11,
          "records": [
            {
              "name": "example.com.",
              "type": "A",
              "ttl": 3600,
              "content": "1.2.3.4"
            },
            {
              "name": "example.com.",
              "type": "AAAA",
              "ttl": 3600,
              "content": "2001:6A8:0:1:210:4BFF:FE4B:4C61"
            },
            ...
          ]
        }
      }
    }
    ```
""".

-behaviour(cowboy_rest).

-include_lib("kernel/include/logger.hrl").

-define(LOG_METADATA, #{domain => [erldns, admin]}).

-export([
    init/2,
    content_types_provided/2,
    resource_exists/2,
    allowed_methods/2,
    delete_resource/2
]).
-export([to_html/2, to_text/2, to_json/2]).

-doc false.
-spec init(cowboy_req:req(), dynamic()) ->
    {cowboy_rest, cowboy_req:req(), dynamic()}.
init(Req, State) ->
    {cowboy_rest, Req, State}.

-doc false.
-spec allowed_methods(cowboy_req:req(), dynamic()) ->
    {[binary()], cowboy_req:req(), dynamic()}.
allowed_methods(Req, State) ->
    {[~"GET", ~"DELETE"], Req, State}.

-doc false.
-spec content_types_provided(cowboy_req:req(), dynamic()) ->
    {[{{binary(), binary(), '*'}, atom()}], cowboy_req:req(), dynamic()}.
content_types_provided(Req, State) ->
    ContentTypesProvided = [
        {{~"application", ~"json", '*'}, to_json},
        {{~"text", ~"html", '*'}, to_html},
        {{~"text", ~"plain", '*'}, to_text}
    ],
    {ContentTypesProvided, Req, State}.

-doc false.
-spec resource_exists(cowboy_req:req(), dynamic()) ->
    {boolean(), cowboy_req:req(), dynamic()}.
resource_exists(Req, State) ->
    Name = cowboy_req:binding(zonename, Req),
    {erldns_zone_cache:is_in_any_zone(Name), Req, State}.

-doc false.
-spec delete_resource(cowboy_req:req(), dynamic()) ->
    {boolean(), cowboy_req:req(), dynamic()}.
delete_resource(Req, State) ->
    Name = cowboy_req:binding(zonename, Req),
    ?LOG_NOTICE(#{what => delete_zone_request, resource => Name}, ?LOG_METADATA),
    erldns_zone_cache:delete_zone(Name),
    {true, Req, State}.

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
    Params = cowboy_req:parse_qs(Req),
    ?LOG_DEBUG(
        #{what => received_get, resource => ZoneName, params => Params},
        ?LOG_METADATA
    ),
    case erldns_zone_cache:lookup_zone(ZoneName) of
        zone_not_found ->
            ?LOG_ERROR(#{what => get_zone_error, error => zone_not_found}, ?LOG_METADATA),
            Resp = "Error getting zone: zone not found",
            {stop, cowboy_req:reply(400, #{}, Resp, Req), State};
        Zone ->
            MaybeMetaOnly = lists:keyfind(~"metaonly", 1, Params),
            Mode = choose_mode(MaybeMetaOnly),
            Json = erldns_zone_codec:encode(Zone, #{mode => Mode}),
            Body = json:encode(Json),
            {Body, Req, State}
    end.

-spec choose_mode(false | {binary(), binary()}) -> atom().
choose_mode({~"metaonly", ~"true"}) ->
    zone_meta_to_json;
choose_mode(_) ->
    zone_to_json.
