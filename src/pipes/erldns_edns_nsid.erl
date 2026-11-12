-module(erldns_edns_nsid).
-moduledoc """
Identify the server to the clients that ask, with NSID (RFC 5001) and the `id.server` and
`hostname.bind` queries (RFC 4892).

- A query carrying an NSID option gets the server's identifier back in an NSID option. Data in the
  query's option is ignored (RFC 5001 §2.2), and a query without the option gets none.
- A TXT query of class CH for `id.server` or `hostname.bind` is answered with the identifier, in a
  TXT record of class CH with a TTL of 0. The record's name is the lowercased query name.

## Configuration

```erlang
{erldns, [
    {packet_pipeline, [
        erldns_edns,
        erldns_questions,
        erldns_edns_nsid,
        erldns_query_throttle,
        erldns_packet_cache,
        ...
    ]},
    {edns_nsid, #{
        id => <<"ns1-ams">> %% 1 to 255 bytes, no default
    }}
]}
```

The pipe is disabled until `id` is set, and an invalid `id` or configuration stops the pipeline
from starting. Any client can ask for the identifier, so pick one that is safe to publish.

The pipe requires `m:erldns_edns` and `m:erldns_questions` before it, and `m:erldns_resolver` and
any `m:erldns_packet_cache` after it, so that queries with and without NSID are cached apart.
""".

-include_lib("dns_erlang/include/dns.hrl").

-behaviour(erldns_pipeline).

-define(MAX_ID_SIZE, 255).
-define(ID_SERVER, [~"id", ~"server"]).
-define(HOSTNAME_BIND, [~"hostname", ~"bind"]).

-export([deps/0, prepare/1, call/2]).

-doc "`c:erldns_pipeline:deps/0` callback.".
-spec deps() -> erldns_pipeline:deps().
deps() ->
    #{
        prerequisites => [erldns_edns, erldns_questions],
        dependents => [erldns_resolver, {optional, erldns_packet_cache}]
    }.

-doc "`c:erldns_pipeline:prepare/1` callback.".
-spec prepare(erldns_pipeline:opts()) -> disabled | erldns_pipeline:opts().
prepare(Opts) ->
    case application:get_env(erldns, edns_nsid, #{}) of
        #{id := Id} when is_binary(Id), 0 < byte_size(Id), byte_size(Id) =< ?MAX_ID_SIZE ->
            Opts#{edns_nsid => Id};
        #{id := Id} ->
            error({invalid_edns_nsid, id, Id});
        #{} ->
            disabled;
        Config ->
            error({invalid_edns_nsid, Config})
    end.

-doc "`c:erldns_pipeline:call/2` callback.".
-spec call(dns:message(), erldns_pipeline:opts()) -> erldns_pipeline:return().
call(
    #dns_message{questions = [#dns_query{class = ?DNS_CLASS_CH, type = ?DNS_TYPE_TXT}]} = Msg,
    #{query_labels := Labels} = Opts
) when Labels =:= ?ID_SERVER; Labels =:= ?HOSTNAME_BIND ->
    Msg1 = server_id_answer(Msg, Opts),
    Opts1 = Opts#{resolved => true},
    Msg2 = maybe_add_nsid(Msg1, Opts1),
    {Msg2, Opts1};
call(Msg, Opts) ->
    maybe_add_nsid(Msg, Opts).

%% The header is set as erldns_resolver sets it, as the resolver will skip this query. The owner is
%% the lowercased name, as the packet cache answers names in any case with the same entry.
-spec server_id_answer(dns:message(), erldns_pipeline:opts()) -> dns:message().
server_id_answer(Msg, #{query_name := Name, edns_nsid := Id}) ->
    Answer = #dns_rr{
        name = Name,
        type = ?DNS_TYPE_TXT,
        class = ?DNS_CLASS_CH,
        ttl = 0,
        data = #dns_rrdata_txt{txt = [Id]}
    },
    Msg#dns_message{
        qr = true,
        aa = true,
        ad = false,
        cd = false,
        rc = ?DNS_RCODE_NOERROR,
        answers = [Answer],
        authority = []
    }.

-spec maybe_add_nsid(dns:message(), erldns_pipeline:opts()) -> dns:message().
maybe_add_nsid(Msg, #{query_edns_options := #{?DNS_EOPTCODE_NSID := _}, edns_nsid := Id}) ->
    erldns_edns:add_option(Msg, #dns_opt_nsid{data = Id});
maybe_add_nsid(Msg, _) ->
    Msg.
