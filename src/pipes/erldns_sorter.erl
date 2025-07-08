-module(erldns_sorter).
-moduledoc """
Sorts the answers, ensuring that CNAME RRs are ordered first.

Should be ran after all resolvers are ran.
""".

-include_lib("dns_erlang/include/dns.hrl").

-behaviour(erldns_pipeline).

-export([call/2]).

-doc "`c:erldns_pipeline:call/2` callback.".
-spec call(dns:message(), erldns_pipeline:opts()) -> dns:message().
call(#dns_message{answers = []} = Msg, _) ->
    Msg;
call(#dns_message{answers = Answers} = Msg, _) ->
    Msg#dns_message{answers = lists:usort(fun sort_fun/2, Answers)}.

-spec sort_fun(dns:rr(), dns:rr()) -> boolean().
sort_fun(
    #dns_rr{type = ?DNS_TYPE_CNAME, data = #dns_rrdata_cname{dname = Name}},
    #dns_rr{type = ?DNS_TYPE_CNAME, name = Name}
) ->
    true;
sort_fun(
    #dns_rr{type = ?DNS_TYPE_CNAME, name = Name},
    #dns_rr{type = ?DNS_TYPE_CNAME, data = #dns_rrdata_cname{dname = Name}}
) ->
    false;
sort_fun(#dns_rr{type = ?DNS_TYPE_CNAME}, #dns_rr{}) ->
    true;
sort_fun(#dns_rr{}, #dns_rr{type = ?DNS_TYPE_CNAME}) ->
    false;
sort_fun(A, B) ->
    A =< B.
