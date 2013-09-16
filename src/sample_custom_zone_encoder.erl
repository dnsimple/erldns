-module(sample_custom_zone_encoder).

-include("dns.hrl").
-include("erldns.hrl").

-export([encode_record/1]).

-define(DNS_TYPE_SAMPLE, 40000).

encode_record({dns_rr, Name, _, ?DNS_TYPE_SAMPLE, Ttl, Data}) ->
  lager:debug("Encoding SAMPLE record"),
  [
    {<<"name">>, erlang:iolist_to_binary(io_lib:format("~s.", [Name]))},
    {<<"type">>, <<"SAMPLE">>},
    {<<"ttl">>, Ttl},
    {<<"content">>, erlang:iolist_to_binary(io_lib:format("~s", [Data]))}
  ];
encode_record(_) ->
  lager:debug("Could not encode record"),
  [].
