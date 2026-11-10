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

The pipe is disabled until `id` is set, and an invalid `id` stops the pipeline from starting. Any
client can ask for the identifier, so pick one that is safe to publish.

The pipe requires `m:erldns_edns` and `m:erldns_questions` before it and `m:erldns_resolver` after
it. Put it before the first `m:erldns_packet_cache` too, so that queries with and without NSID are
cached apart.
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
    #{prerequisites => [erldns_edns, erldns_questions], dependents => [erldns_resolver]}.

-doc "`c:erldns_pipeline:prepare/1` callback.".
-spec prepare(erldns_pipeline:opts()) -> disabled | erldns_pipeline:opts().
prepare(Opts) ->
    case application:get_env(erldns, edns_nsid, #{}) of
        #{id := Id} when is_binary(Id), 0 < byte_size(Id), byte_size(Id) =< ?MAX_ID_SIZE ->
            Opts#{nsid => Id};
        #{id := Id} ->
            error({invalid_edns_nsid, id, Id});
        _ ->
            disabled
    end.

-doc "`c:erldns_pipeline:call/2` callback.".
-spec call(dns:message(), erldns_pipeline:opts()) -> erldns_pipeline:return().
call(Msg, Opts) ->
    case is_server_id_query(Msg, Opts) of
        true -> {add_nsid(server_id_answer(Msg, Opts), Opts), Opts#{resolved => true}};
        false -> add_nsid(Msg, Opts)
    end.

-spec is_server_id_query(dns:message(), erldns_pipeline:opts()) -> boolean().
is_server_id_query(
    #dns_message{questions = [#dns_query{class = ?DNS_CLASS_CH, type = ?DNS_TYPE_TXT}]},
    #{query_labels := Labels}
) ->
    Labels =:= ?ID_SERVER orelse Labels =:= ?HOSTNAME_BIND;
is_server_id_query(_, _) ->
    false.

%% The header is set as erldns_resolver sets it, as the resolver will skip this query. The owner is
%% the lowercased name, as the packet cache answers names in any case with the same entry.
-spec server_id_answer(dns:message(), erldns_pipeline:opts()) -> dns:message().
server_id_answer(Msg, #{query_name := Name, nsid := Id}) ->
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

-spec add_nsid(dns:message(), erldns_pipeline:opts()) -> dns:message().
add_nsid(Msg, #{query_edns_options := #{?DNS_EOPTCODE_NSID := _}, nsid := Id}) ->
    erldns_edns:add_option(Msg, #dns_opt_nsid{data = Id});
add_nsid(Msg, _) ->
    Msg.
