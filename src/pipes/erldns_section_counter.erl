-module(erldns_section_counter).
-moduledoc """
Counts the sections and updates the respective header fields at once.

Should be ran after all resolvers are ran.
""".

-include_lib("dns_erlang/include/dns.hrl").

-behaviour(erldns_pipeline).

-export([call/2]).

-doc "`c:erldns_pipeline:call/2` callback.".
-spec call(dns:message(), erldns_pipeline:opts()) -> dns:message().
call(#dns_message{} = Msg, _) ->
    Msg#dns_message{
        anc = length(Msg#dns_message.answers),
        auc = length(Msg#dns_message.authority),
        adc = length(Msg#dns_message.additional)
    }.
