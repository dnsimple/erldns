-module(erldns_edns_ecs).
-moduledoc """
Support EDNS Client Subnet (ECS, RFC 7871), so that pipes can tailor answers to the client's
network.

A resolver tells an authoritative server which network its client is in with an ECS option. When a
query carries one:

- A malformed option gets FORMERR (RFC 7871 §6 and §7.2.1): a family other than IPv4 or IPv6, a
  source prefix longer than the address, an address with more or fewer bytes than the prefix needs
  or with bits set past it, or a scope other than 0.
- Otherwise the client's network goes in the `client_subnet` pipeline option, as
  `{Address, PrefixLength}`, and the response sends the option back with the query's family, source
  prefix and address (§7.2.1). Its scope is 0, which means the answer is good for every network,
  unless the pipe that chose the answer by `client_subnet` sets it with `set_scope/2`.

A query without ECS gets none back, and `client_subnet` is `undefined`. Only the first ECS option of
a query counts.

## Configuration

The pipe is not in the default pipeline. It requires `m:erldns_edns` before it, and
`m:erldns_resolver` and any `m:erldns_packet_cache` after it: the cache then looks answers up by the
client's network, and an answer chosen for one network is not given to another.

```erlang
{erldns, [
    {packet_pipeline, [
        erldns_edns,
        erldns_questions,
        erldns_edns_ecs,
        erldns_query_throttle,
        erldns_packet_cache,
        ...
    ]}
]}
```

> #### Warning {: .warning}
>
> Answering with ECS leads large resolvers to send their clients' networks, which are personal data,
> and splits packet cache entries by network. Only add this pipe when a pipe tailors answers.

## Tailoring answers

A pipe that chooses the answer by `client_subnet` runs after the resolver, and calls `set_scope/2`
with the number of leading bits of the address that the answer depends on. Keep the scope at 0 for
referrals and negative answers (RFC 7871 §7.4).

The pipe should only act when `auth_zone` is a zone. An answer from the packet cache runs through
the rest of the pipeline too, with `auth_zone` as `zone_not_found`, and it is tailored already.
""".

-include_lib("dns_erlang/include/dns.hrl").

-behaviour(erldns_pipeline).

%% Address family numbers, as assigned by IANA.
-define(FAMILY_IPV4, 1).
-define(FAMILY_IPV6, 2).

-export([deps/0, prepare/1, call/2]).
-export([set_scope/2]).

-doc "The client's network, as `{Address, PrefixLength}`.".
-type client_subnet() :: {inet:ip_address(), 0..128}.
-export_type([client_subnet/0]).

-doc "`c:erldns_pipeline:deps/0` callback.".
-spec deps() -> erldns_pipeline:deps().
deps() ->
    #{
        prerequisites => [erldns_edns],
        dependents => [erldns_resolver, {optional, erldns_packet_cache}]
    }.

-doc "`c:erldns_pipeline:prepare/1` callback.".
-spec prepare(erldns_pipeline:opts()) -> erldns_pipeline:opts().
prepare(Opts) ->
    Opts#{client_subnet => undefined}.

-doc "`c:erldns_pipeline:call/2` callback.".
-spec call(dns:message(), erldns_pipeline:opts()) -> erldns_pipeline:return().
call(Msg, #{query_edns_options := #{?DNS_EOPTCODE_ECS := Ecs}} = Opts) ->
    case client_subnet(Ecs) of
        {ok, Subnet} ->
            Msg1 = erldns_edns:add_option(Msg, Ecs),
            Opts1 = Opts#{client_subnet => Subnet},
            {Msg1, Opts1};
        error ->
            {stop, formerr(Msg)}
    end;
call(Msg, _) ->
    Msg.

-doc """
Set the scope of the response's ECS option: how many leading bits of the client's address the
answer depends on, at most 32 for IPv4 and 128 for IPv6.

Does nothing when the response has no ECS option.
""".
-spec set_scope(dns:message(), 0..128) -> dns:message().
set_scope(Msg, Scope) when is_integer(Scope), 0 =< Scope ->
    WithScope = fun(Options) -> [with_scope(Option, Scope) || Option <- Options] end,
    erldns_edns:update_options(Msg, WithScope).

-spec with_scope(dns:optrr_elem(), 0..128) -> dns:optrr_elem().
with_scope(#dns_opt_ecs{family = Family} = Ecs, Scope) ->
    case address_bits(Family) of
        {ok, Bits} when Scope =< Bits -> Ecs#dns_opt_ecs{scope_prefix_length = Scope};
        _ -> error({invalid_scope, Scope})
    end;
with_scope(Option, _) ->
    Option.

-spec client_subnet(dns:opt_ecs()) -> {ok, client_subnet()} | error.
client_subnet(#dns_opt_ecs{
    family = Family, source_prefix_length = Source, scope_prefix_length = 0, address = Address
}) ->
    maybe
        {ok, Bits} ?= address_bits(Family),
        true ?= Source =< Bits andalso byte_size(Address) =:= (Source + 7) div 8,
        Padding = bit_size(Address) - Source,
        <<_:Source, 0:Padding>> ?= Address,
        Ip = address(Family, Address),
        {ok, {Ip, Source}}
    else
        _ -> error
    end;
client_subnet(_) ->
    error.

-spec address_bits(dns:uint16()) -> {ok, 32 | 128} | error.
address_bits(?FAMILY_IPV4) -> {ok, 32};
address_bits(?FAMILY_IPV6) -> {ok, 128};
address_bits(_) -> error.

-spec address(?FAMILY_IPV4 | ?FAMILY_IPV6, binary()) -> inet:ip_address().
address(?FAMILY_IPV4, Address) ->
    <<A, B, C, D>> = pad(Address, 4),
    {A, B, C, D};
address(?FAMILY_IPV6, Address) ->
    <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>> = pad(Address, 16),
    {A, B, C, D, E, F, G, H}.

-spec pad(binary(), 4 | 16) -> binary().
pad(Address, Size) ->
    Padding = (Size - byte_size(Address)) * 8,
    <<Address/binary, 0:Padding>>.

%% The pipeline stops here, so the header counts are set too.
-spec formerr(dns:message()) -> dns:message().
formerr(Msg) ->
    Msg#dns_message{
        qr = true,
        aa = false,
        ad = false,
        rc = ?DNS_RCODE_FORMERR,
        anc = 0,
        auc = 0,
        answers = [],
        authority = []
    }.
