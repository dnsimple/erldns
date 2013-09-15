-module(erldns_zone_encoder).

-export([encode_record/1]).

-include("dns.hrl").
-include("erldns.hrl").

encode_record(Record) ->
  [
    {<<"name">>, erlang:iolist_to_binary(io_lib:format("~s.", [Record#dns_rr.name]))},
    {<<"type">>, dns:type_name(Record#dns_rr.type)},
    {<<"ttl">>, Record#dns_rr.ttl},
    {<<"content">>, encode_data(Record#dns_rr.data)}
  ].

encode_data({dns_rrdata_soa, Mname, Rname, Serial, Refresh, Retry, Expire, Minimum}) ->
  erlang:iolist_to_binary(io_lib:format("~s. ~s. (~w ~w ~w ~w ~w)", [Mname, Rname, Serial, Refresh, Retry, Expire, Minimum]));
encode_data({dns_rrdata_ns, Dname}) ->
  erlang:iolist_to_binary(io_lib:format("~s.", [Dname]));
encode_data({dns_rrdata_a, Address}) ->
  list_to_binary(inet_parse:ntoa(Address));
encode_data({dns_rrdata_aaaa, Address}) ->
  list_to_binary(inet_parse:ntoa(Address));
encode_data({dns_rrdata_cname, Dname}) ->
  erlang:iolist_to_binary(io_lib:format("~s.", [Dname]));
encode_data({dns_rrdata_mx, Preference, Dname}) ->
  erlang:iolist_to_binary(io_lib:format("~w ~s.", [Preference, Dname]));
encode_data({dns_rrdata_hinfo, Cpu, Os}) ->
  erlang:iolist_to_binary(io_lib:format("~w ~w", [Cpu, Os]));
% RP
encode_data({dns_rrdata_txt, Text}) ->
  erlang:iolist_to_binary(io_lib:format("~s", [Text]));
encode_data({dns_rrdata_spf, [Data]}) ->
  erlang:iolist_to_binary(io_lib:format("~s", [Data]));
encode_data({dns_rrdata_sshfp, Alg, Fptype, Fp}) ->
  erlang:iolist_to_binary(io_lib:format("~w ~w ~s", [Alg, Fptype, Fp]));
encode_data({dns_rrdata_srv, Priority, Weight, Port, Dname}) ->
  erlang:iolist_to_binary(io_lib:format("~w ~w ~w ~s.", [Priority, Weight, Port, Dname]));
encode_data({dns_rrdata_naptr, Order, Preference, Flags, Services, Regexp, Replacements}) ->
  erlang:iolist_to_binary(io_lib:format("~w ~w ~s ~s ~s ~s", [Order, Preference, Flags, Services, Regexp, Replacements]));
encode_data(Data) ->
  lager:debug("Unable to encode data: ~p", [Data]),
  <<"">>.
