-module(erldns_records).
-moduledoc false.

-include_lib("dns_erlang/include/dns.hrl").

% Wildcard functions
-export([
    optionally_convert_wildcard/2,
    wildcard_qname/1
]).
% SOA TTL functions
-export([
    minimum_soa_ttl/2,
    rewrite_soa_ttl/1
]).
% Matcher functions
-export([
    match_name/1,
    match_type/1,
    match_name_and_type/2,
    match_types/1,
    match_wildcard/0,
    match_not_wildcard/0,
    match_delegation/1,
    match_type_covered/1,
    match_wildcard_label/0
]).
-export([
    default_ttl/1,
    default_priority/1,
    root_hints/0,
    replace_name/1
]).

-doc "If given Name is a wildcard name then the original qname needs to be returned in its place.".
-spec optionally_convert_wildcard(dns:dname(), dns:dname()) -> dns:dname().
optionally_convert_wildcard(Name, Qname) ->
    case dns:dname_to_labels(Name) of
        [~"*" | _] ->
            Qname;
        [_ | _] ->
            Name
    end.

-doc """
Get a wildcard variation of a Qname.

Replaces the leading label with an asterisk for wildcard lookup.
""".
-spec wildcard_qname(dns:dname()) -> dns:dname().
wildcard_qname(Qname) ->
    [_ | Rest] = dns:dname_to_labels(Qname),
    dns:labels_to_dname([~"*" | Rest]).

-doc "Return the TTL value or 3600 if it is undefined.".
-spec default_ttl(integer() | undefined) -> integer().
default_ttl(undefined) ->
    3600;
default_ttl(TTL) ->
    TTL.

-doc "Return the Priority value or 0 if it is undefined.".
-spec default_priority(integer() | undefined) -> integer().
default_priority(undefined) ->
    0;
default_priority(Priority) ->
    Priority.

-doc """
Applies a minimum TTL based on the SOA minimum value.

The first argument is the Record that is being updated.
The second argument is the SOA RR Data.
""".
-spec minimum_soa_ttl(dns:rr(), dns:rrdata()) -> dns:rr().
minimum_soa_ttl(#dns_rr{ttl = RecTtl} = Record, #dns_rrdata_soa{minimum = SoaMinimum}) ->
    Record#dns_rr{ttl = erlang:min(SoaMinimum, RecTtl)};
minimum_soa_ttl(#dns_rr{} = Record, _) ->
    Record.

-doc """
According to RFC 2308 the TTL for the SOA record in an NXDOMAIN response
must be set to the value of the minimum field in the SOA content.
""".
-spec rewrite_soa_ttl(dns:message()) -> dns:message().
rewrite_soa_ttl(Message) ->
    rewrite_soa_ttl(Message, Message#dns_message.authority, []).

rewrite_soa_ttl(Message, [], NewAuthority) ->
    Message#dns_message{authority = lists:reverse(NewAuthority)};
rewrite_soa_ttl(Message, [R | Rest], NewAuthority) ->
    rewrite_soa_ttl(Message, Rest, [minimum_soa_ttl(R, R#dns_rr.data) | NewAuthority]).

%% Various matching functions.

-spec match_name(dns:dname()) -> fun((dns:rr()) -> boolean()).
match_name(Name) ->
    fun(#dns_rr{name = RRName}) -> RRName =:= Name end.

-spec match_type(dns:type()) -> fun((dns:rr()) -> boolean()).
match_type(Type) ->
    fun(#dns_rr{type = RRType}) -> RRType =:= Type end.

-spec match_name_and_type(dns:dname(), dns:type()) -> fun((dns:rr()) -> boolean()).
match_name_and_type(Name, Type) ->
    fun(#dns_rr{name = RRName, type = RRType}) -> (RRName =:= Name) andalso (RRType =:= Type) end.

-spec match_types([dns:type()]) -> fun((dns:rr()) -> boolean()).
match_types(Types) ->
    fun(#dns_rr{type = RRType}) -> lists:member(RRType, Types) end.

-spec match_wildcard() -> fun((dns:rr()) -> boolean()).
match_wildcard() ->
    fun(#dns_rr{name = RRName}) -> lists:member(~"*", dns:dname_to_labels(RRName)) end.

-spec match_not_wildcard() -> fun((dns:rr()) -> boolean()).
match_not_wildcard() ->
    fun(#dns_rr{name = RRName}) -> not lists:member(~"*", dns:dname_to_labels(RRName)) end.

-spec match_wildcard_label() -> fun((binary()) -> boolean()).
match_wildcard_label() ->
    fun(L) -> L =:= ~"*" end.

-spec match_delegation(dns:dname()) -> fun((dns:rr()) -> boolean()).
match_delegation(Name) ->
    fun(#dns_rr{data = Data}) -> #dns_rrdata_ns{dname = Name} =:= Data end.

-spec match_type_covered(dns:type()) -> fun((dns:rr()) -> boolean()).
match_type_covered(Qtype) ->
    fun(#dns_rr{data = #dns_rrdata_rrsig{type_covered = TypeCovered}}) -> TypeCovered =:= Qtype end.

-spec replace_name(dns:dname()) -> fun((dns:rr()) -> dns:rr()).
replace_name(Name) ->
    fun(#dns_rr{} = R) -> R#dns_rr{name = Name} end.

-spec root_hints() -> {[dns:rr()], [dns:rr()]}.
root_hints() ->
    {
        [
            #dns_rr{
                name = ~"",
                type = ?DNS_TYPE_NS,
                ttl = 518400,
                data = #dns_rrdata_ns{dname = ~"a.root-servers.net"}
            },
            #dns_rr{
                name = ~"",
                type = ?DNS_TYPE_NS,
                ttl = 518400,
                data = #dns_rrdata_ns{dname = ~"b.root-servers.net"}
            },
            #dns_rr{
                name = ~"",
                type = ?DNS_TYPE_NS,
                ttl = 518400,
                data = #dns_rrdata_ns{dname = ~"c.root-servers.net"}
            },
            #dns_rr{
                name = ~"",
                type = ?DNS_TYPE_NS,
                ttl = 518400,
                data = #dns_rrdata_ns{dname = ~"d.root-servers.net"}
            },
            #dns_rr{
                name = ~"",
                type = ?DNS_TYPE_NS,
                ttl = 518400,
                data = #dns_rrdata_ns{dname = ~"e.root-servers.net"}
            },
            #dns_rr{
                name = ~"",
                type = ?DNS_TYPE_NS,
                ttl = 518400,
                data = #dns_rrdata_ns{dname = ~"f.root-servers.net"}
            },
            #dns_rr{
                name = ~"",
                type = ?DNS_TYPE_NS,
                ttl = 518400,
                data = #dns_rrdata_ns{dname = ~"g.root-servers.net"}
            },
            #dns_rr{
                name = ~"",
                type = ?DNS_TYPE_NS,
                ttl = 518400,
                data = #dns_rrdata_ns{dname = ~"h.root-servers.net"}
            },
            #dns_rr{
                name = ~"",
                type = ?DNS_TYPE_NS,
                ttl = 518400,
                data = #dns_rrdata_ns{dname = ~"i.root-servers.net"}
            },
            #dns_rr{
                name = ~"",
                type = ?DNS_TYPE_NS,
                ttl = 518400,
                data = #dns_rrdata_ns{dname = ~"j.root-servers.net"}
            },
            #dns_rr{
                name = ~"",
                type = ?DNS_TYPE_NS,
                ttl = 518400,
                data = #dns_rrdata_ns{dname = ~"k.root-servers.net"}
            },
            #dns_rr{
                name = ~"",
                type = ?DNS_TYPE_NS,
                ttl = 518400,
                data = #dns_rrdata_ns{dname = ~"l.root-servers.net"}
            },
            #dns_rr{
                name = ~"",
                type = ?DNS_TYPE_NS,
                ttl = 518400,
                data = #dns_rrdata_ns{dname = ~"m.root-servers.net"}
            }
        ],
        [
            #dns_rr{
                name = ~"a.root-servers.net",
                type = ?DNS_TYPE_A,
                ttl = 3600000,
                data = #dns_rrdata_a{ip = {198, 41, 0, 4}}
            },
            #dns_rr{
                name = ~"b.root-servers.net",
                type = ?DNS_TYPE_A,
                ttl = 3600000,
                data = #dns_rrdata_a{ip = {192, 228, 79, 201}}
            },
            #dns_rr{
                name = ~"c.root-servers.net",
                type = ?DNS_TYPE_A,
                ttl = 3600000,
                data = #dns_rrdata_a{ip = {192, 33, 4, 12}}
            },
            #dns_rr{
                name = ~"d.root-servers.net",
                type = ?DNS_TYPE_A,
                ttl = 3600000,
                data = #dns_rrdata_a{ip = {128, 8, 10, 90}}
            },
            #dns_rr{
                name = ~"e.root-servers.net",
                type = ?DNS_TYPE_A,
                ttl = 3600000,
                data = #dns_rrdata_a{ip = {192, 203, 230, 10}}
            },
            #dns_rr{
                name = ~"f.root-servers.net",
                type = ?DNS_TYPE_A,
                ttl = 3600000,
                data = #dns_rrdata_a{ip = {192, 5, 5, 241}}
            },
            #dns_rr{
                name = ~"g.root-servers.net",
                type = ?DNS_TYPE_A,
                ttl = 3600000,
                data = #dns_rrdata_a{ip = {192, 112, 36, 4}}
            },
            #dns_rr{
                name = ~"h.root-servers.net",
                type = ?DNS_TYPE_A,
                ttl = 3600000,
                data = #dns_rrdata_a{ip = {128, 63, 2, 53}}
            },
            #dns_rr{
                name = ~"i.root-servers.net",
                type = ?DNS_TYPE_A,
                ttl = 3600000,
                data = #dns_rrdata_a{ip = {192, 36, 148, 17}}
            },
            #dns_rr{
                name = ~"j.root-servers.net",
                type = ?DNS_TYPE_A,
                ttl = 3600000,
                data = #dns_rrdata_a{ip = {192, 58, 128, 30}}
            },
            #dns_rr{
                name = ~"k.root-servers.net",
                type = ?DNS_TYPE_A,
                ttl = 3600000,
                data = #dns_rrdata_a{ip = {193, 0, 14, 129}}
            },
            #dns_rr{
                name = ~"l.root-servers.net",
                type = ?DNS_TYPE_A,
                ttl = 3600000,
                data = #dns_rrdata_a{ip = {198, 32, 64, 12}}
            },
            #dns_rr{
                name = ~"m.root-servers.net",
                type = ?DNS_TYPE_A,
                ttl = 3600000,
                data = #dns_rrdata_a{ip = {202, 12, 27, 33}}
            }
        ]
    }.
