-module(erldns_zone_encoder_test).

-feature(maybe_expr, enable).

-include_lib("dns_erlang/include/dns.hrl").
-include_lib("erldns/include/erldns.hrl").
-include_lib("eunit/include/eunit.hrl").

zone_meta_to_json_with_valid_zone_test() ->
    {ok, Pid} = erldns_zone_parser:start_link(),
    erldns_zone_cache:create(zones),
    erldns_zone_cache:create(zone_records_typed),

    Z = #zone{
        name = <<"example.com">>,
        authority = [#dns_rr{name = <<"example.com">>, type = ?DNS_TYPE_SOA}]
    },

    JSON = erldns_zone_encoder:zone_meta_to_json(Z),
    ?assert(is_binary(JSON)),

    #{
        <<"erldns">> := #{
            <<"zone">> := #{
                <<"name">> := <<"example.com">>,
                <<"version">> := _,
                <<"records_count">> := _
            }
        }
    } = json:decode(JSON),

    gen_server:stop(Pid).
