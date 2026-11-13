-module(erldns_zone_context).
-moduledoc """
A zone pipe that drops the JSON records this node doesn't serve, by their `context`.

It reads `context_options` from the `zones` configuration when the pipeline is prepared, and is
disabled without them. See [Contexts](priv/zones/ZONES.md#contexts). It goes before
`m:erldns_zone_standard`, as decoded records have no context.
""".

-behaviour(erldns_zone_pipeline).

-export([deps/0, prepare/1, call/2]).

-doc "`c:erldns_zone_pipeline:deps/0` callback.".
-spec deps() -> erldns_pipeline:deps().
deps() ->
    #{dependents => [{optional, erldns_zone_standard}]}.

-doc "`c:erldns_zone_pipeline:prepare/1` callback.".
-spec prepare(erldns_zone_pipeline:opts()) -> disabled | erldns_zone_pipeline:opts().
prepare(Opts) ->
    case application:get_env(erldns, zones, #{}) of
        #{context_options := ContextOptions} when is_map(ContextOptions) ->
            MatchEmpty = maps:get(match_empty, ContextOptions, false),
            Allow = maps:get(allow, ContextOptions, []),
            AllowSet = sets:from_list(Allow, [{version, 2}]),
            Opts#{?MODULE => {MatchEmpty, AllowSet}};
        _ ->
            disabled
    end.

-doc "`c:erldns_zone_pipeline:call/2` callback.".
-spec call([erldns_zone_pipeline:entry()], erldns_zone_pipeline:opts()) ->
    [erldns_zone_pipeline:entry()].
call(Entries, #{?MODULE := Context}) ->
    [Entry || Entry <- Entries, is_served(Entry, Context)].

is_served(#{~"context" := Contexts}, {MatchEmpty, AllowSet}) ->
    matches_empty(MatchEmpty, Contexts) orelse is_allowed(Contexts, AllowSet);
is_served(_, _) ->
    true.

matches_empty(true, []) -> true;
matches_empty(_, _) -> false.

is_allowed(Contexts, AllowSet) ->
    lists:any(fun(Context) -> sets:is_element(Context, AllowSet) end, Contexts).
