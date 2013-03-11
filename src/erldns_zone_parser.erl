-module(erldns_zone_parser).

-export([zones_to_erlang/1, zone_to_erlang/1]).

-include("dns.hrl").
-include("erldns.hrl").

zones_to_erlang(Zones) -> zones_to_erlang(Zones, []).

% Internal
zones_to_erlang([], Zones) -> Zones;

zones_to_erlang([Zone|Rest], Zones) ->
  ParsedZone = zone_to_erlang(Zone),
  zones_to_erlang(Rest, Zones ++ [ParsedZone]).

%% Takes a JSON zone and turns it into the tuple {Name, Records}.
zone_to_erlang([{<<"name">>, Name}, {<<"records">>, JsonRecords}]) ->
  Records = lists:map(
    fun(JsonRecord) ->
        json_record_to_erlang(JsonRecord)
    end, JsonRecords),

  FilteredRecords = lists:filter(
    fun(R) ->
        case R of
          {} -> false;
          _ -> true
        end
    end, Records),

  {Name, FilteredRecords}.

% Internal converters
json_record_to_erlang([{<<"name">>, Name}, {<<"type">>, <<"SOA">>}, {<<"data">>, [{<<"mname">>, Mname}, {<<"rname">>, Rname}, {<<"serial">>, Serial}, {<<"refresh">>, Refresh}, {<<"retry">>, Retry}, {<<"expire">>, Expire},{<<"minimum">>, Minimum}]}, {<<"ttl">>, Ttl}]) ->
  #dns_rr{name = Name, type = ?DNS_TYPE_SOA, data = #dns_rrdata_soa{mname = Mname, rname = Rname, serial = Serial, refresh = Refresh, retry = Retry, expire = Expire, minimum = Minimum}, ttl = Ttl};

json_record_to_erlang([{<<"name">>, Name}, {<<"type">>, <<"NS">>}, {<<"data">>, [{<<"dname">>, Dname}]}, {<<"ttl">>, Ttl}]) ->
  #dns_rr{name = Name, type = ?DNS_TYPE_NS, data = #dns_rrdata_ns{dname = Dname}, ttl = Ttl};

json_record_to_erlang([{<<"name">>, Name}, {<<"type">>, <<"A">>}, {<<"data">>, [{<<"ip">>, Ip}]}, {<<"ttl">>, Ttl}]) ->
  case inet_parse:address(binary_to_list(Ip)) of
    {ok, Address} ->
      #dns_rr{name = Name, type = ?DNS_TYPE_A, data = #dns_rrdata_a{ip = Address}, ttl = Ttl};
    {error, Reason} ->
      lager:error("Failed to parse A record address ~p: ~p", [Ip, Reason]),
      {}
  end;

json_record_to_erlang([{<<"name">>, Name}, {<<"type">>, <<"AAAA">>}, {<<"data">>, [{<<"ip">>, Ip}]}, {<<"ttl">>, Ttl}]) ->
  case inet_parse:address(binary_to_list(Ip)) of
    {ok, Address} ->
      #dns_rr{name = Name, type = ?DNS_TYPE_AAAA, data = #dns_rrdata_aaaa{ip = Address}, ttl = Ttl};
    {error, Reason} ->
      lager:error("Failed to parse AAAA record address ~p: ~p", [Ip, Reason]),
      {}
  end;

json_record_to_erlang([{<<"name">>, Name}, {<<"type">>, <<"CNAME">>}, {<<"data">>, [{<<"dname">>, Dname}]}, {<<"ttl">>, Ttl}]) ->
  #dns_rr{name = Name, type = ?DNS_TYPE_CNAME, data = #dns_rrdata_cname{dname = Dname}, ttl = Ttl};

json_record_to_erlang([{<<"name">>, Name}, {<<"type">>, <<"MX">>}, {<<"data">>, [{<<"preference">>, Preference}, {<<"exchange">>, Exchange}]}, {<<"ttl">>, Ttl}]) ->
  #dns_rr{name = Name, type = ?DNS_TYPE_MX, data = #dns_rrdata_mx{exchange = Exchange, preference = Preference}, ttl = Ttl};

json_record_to_erlang([{<<"name">>, Name}, {<<"type">>, <<"TXT">>}, {<<"data">>, [{<<"txt">>, Text}]}, {<<"ttl">>, Ttl}]) ->
  #dns_rr{name = Name, type = ?DNS_TYPE_TXT, data = #dns_rrdata_txt{txt = [Text]}, ttl = Ttl};

json_record_to_erlang([{<<"name">>, Name}, {<<"type">>, <<"SPF">>}, {<<"data">>, [{<<"spf">>, Spf}]}, {<<"ttl">>, Ttl}]) ->
  #dns_rr{name = Name, type = ?DNS_TYPE_SPF, data = #dns_rrdata_spf{spf = [Spf]}, ttl = Ttl};

json_record_to_erlang([{<<"name">>,Name},{<<"type">>,<<"PTR">>},{<<"data">>,[{<<"dname">>, Dname}]},{<<"ttl">>, Ttl}]) ->
  #dns_rr{name = Name, type = ?DNS_TYPE_PTR, data = #dns_rrdata_ptr{dname = Dname}, ttl = Ttl};

json_record_to_erlang([{<<"name">>,Name},{<<"type">>,<<"SSHFP">>},{<<"data">>,[{<<"alg">>,Alg},{<<"fptype">>,Fptype},{<<"fp">>,Fp}]},{<<"ttl">>,Ttl}]) ->
  #dns_rr{name = Name, type = ?DNS_TYPE_SSHFP, data = #dns_rrdata_sshfp{alg = Alg, fp_type = Fptype, fp = Fp}, ttl = Ttl};

json_record_to_erlang([{<<"name">>, Name}, {<<"type">>, <<"SRV">>}, {<<"data">>, [{<<"priority">>, Priority}, {<<"weight">>, Weight}, {<<"port">>, Port}, {<<"target">>, Target}]}, {<<"ttl">>, Ttl}]) ->
  #dns_rr{name = Name, type = ?DNS_TYPE_SRV, data = #dns_rrdata_srv{priority = Priority, weight = Weight, port = Port, target = Target}, ttl = Ttl};

json_record_to_erlang([{<<"name">>, Name}, {<<"type">>, <<"NAPTR">>}, {<<"data">>, [{<<"order">>, Order}, {<<"preference">>, Preference}, {<<"flags">>, Flags}, {<<"services">>, Services}, {<<"regexp">>, Regexp}, {<<"replacement">>, Replacement}]}, {<<"ttl">>, Ttl}]) ->
  #dns_rr{name = Name, type = ?DNS_TYPE_NAPTR, data = #dns_rrdata_naptr{order = Order, preference = Preference, flags = Flags, services = Services, regexp = Regexp, replacement = Replacement}, ttl = Ttl};

json_record_to_erlang(JsonRecord) ->
  lager:info("Unsupported record ~p", [JsonRecord]),
  {}.

