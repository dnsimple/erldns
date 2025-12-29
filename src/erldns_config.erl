-module(erldns_config).
-moduledoc "Provide application-wide configuration access.".

-export([
    use_root_hints/0,
    ingress_udp_request_timeout/0
]).

-define(DEFAULT_UDP_PROCESS_TIMEOUT, 500).

-doc "Use IANA DNS root servers as hints".
-spec use_root_hints() -> boolean().
use_root_hints() ->
    case application:get_env(erldns, use_root_hints) of
        {ok, Flag} when is_boolean(Flag) ->
            Flag;
        _ ->
            true
    end.

-doc "Timeout in milliseconds before which an UDP request must be completed.".
-spec ingress_udp_request_timeout() -> non_neg_integer().
ingress_udp_request_timeout() ->
    case application:get_env(erldns, ingress_udp_request_timeout) of
        {ok, UdpTimeout} when is_integer(UdpTimeout), 0 =< UdpTimeout ->
            UdpTimeout;
        _ ->
            ?DEFAULT_UDP_PROCESS_TIMEOUT
    end.
