-module(erldns_config).
-moduledoc "Provide application-wide configuration access.".

-export([
    use_root_hints/0
]).

-doc "Use IANA DNS root servers as hints".
-spec use_root_hints() -> boolean().
use_root_hints() ->
    case application:get_env(erldns, use_root_hints) of
        {ok, Flag} when is_boolean(Flag) ->
            Flag;
        _ ->
            true
    end.
