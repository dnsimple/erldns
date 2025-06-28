-module(erldns_resolver_recursive).
-moduledoc """
DNS recursion.

Stub module, as `erldns` does not implement recursion (yet),
this module simply sets the recursion bit as false.
""".

-include_lib("dns_erlang/include/dns.hrl").

-behaviour(erldns_pipeline).

-export([call/2]).

%% Set the RA bit to false as we do not handle recursive queries.
-doc "`c:erldns_pipeline:call/2` callback.".
-spec call(dns:message(), erldns_pipeline:opts()) -> erldns_pipeline:return().
call(#dns_message{} = Msg, _) ->
    Msg#dns_message{ra = false}.
