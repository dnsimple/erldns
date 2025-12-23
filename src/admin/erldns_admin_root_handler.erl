-module(erldns_admin_root_handler).
-moduledoc """
Support for the erldns Admin API root resource at path `/`.

The following is implemented:
- `DELETE`: Reset all listener queues
- `GET`: Returns name and version information for all zones in the cache.

    The response JSON body looks like the following:
    ```json
    {
      "erldns": {
        "zones": {
          "count": 2,
          "versions": [
            {
              "name": "example.com",
              "version": "v1.2.3"
            },
            {
              "name": "example.org",
              "version": "v4.5.6"
            }
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
-spec delete_resource(cowboy_req:req(), dynamic()) ->
    {boolean(), cowboy_req:req(), dynamic()}.
delete_resource(Req, State) ->
    ?LOG_WARNING(#{what => resetting_listener_queues}, ?LOG_METADATA),
    {erldns_listeners:reset_queues(), Req, State}.

-doc false.
-spec to_json(cowboy_req:req(), dynamic()) ->
    {cowboy_req:resp_body(), cowboy_req:req(), dynamic()}.
to_json(Req, State) ->
    ZoneNamesAndVersionsForJson = lists:map(
        fun process_name_version/1,
        erldns_zone_cache:zone_names_and_versions()
    ),
    Body = json:encode(#{
        ~"erldns" => #{
            ~"zones" => #{
                ~"count" => length(ZoneNamesAndVersionsForJson),
                ~"versions" => ZoneNamesAndVersionsForJson
            }
        }
    }),
    {Body, Req, State}.

-spec process_name_version({binary(), binary()}) -> #{binary() => binary()}.
process_name_version({Name, Version}) ->
    #{~"name" => Name, ~"version" => Version}.
