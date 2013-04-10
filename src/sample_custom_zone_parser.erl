-module(sample_custom_zone_parser).

-include("dns.hrl").
-include("erldns.hrl").

-export([json_record_to_erlang/1]).

-define(DNS_TYPE_SAMPLE, 40000).

json_record_to_erlang([Name, <<"SAMPLE">>, Ttl, Data]) ->
  #dns_rr{name = Name, type = ?DNS_TYPE_SAMPLE, data = proplists:get_value(<<"dname">>, Data), ttl = Ttl};

json_record_to_erlang([_Name, _Type, _Ttl, _Data]) -> {}.
