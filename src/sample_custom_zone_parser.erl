-module(sample_custom_zone_parser).

-include("dns.hrl").
-include("erldns.hrl").

-export([json_record_to_erlang/1]).

-define(DNS_TYPE_SAMPLE, 40000).

json_record_to_erlang([{<<"name">>, Name}, {<<"type">>, <<"SAMPLE">>}, {<<"data">>, [{<<"dname">>, Dname}]}, {<<"ttl">>, Ttl}]) ->
  lager:info("Converting SAMPLE record from JSON to Erlang"),
  #dns_rr{name = Name, type = ?DNS_TYPE_SAMPLE, data = Dname, ttl = Ttl};
json_record_to_erlang(_JsonRecord) -> {}.
