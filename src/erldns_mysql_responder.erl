-module(erldns_mysql_responder).

-include("dns.hrl").
-include("mysql.hrl").

-export([answer/2]).

answer(Qname, Qtype) ->
  lager:debug("~p:answer(~p, ~p)~n", [?MODULE, Qname, Qtype]),
  Records = lists:flatten(lists:map(fun row_to_record/1, lookup(Qname, Qtype))),
  case Qtype of
    ?DNS_TYPE_CNAME_BSTR -> Records;
    _ -> resolve_cnames(Records)
  end.

lookup(Qname, Qtype) ->
  lager:debug("~p:lookup(~p, ~p)~n", [?MODULE, Qname, Qtype]),
  {data, Data} = case Qtype of
    ?DNS_TYPE_ANY_BSTR ->
      mysql:prepare(select_records, <<"select * from records where name = ?">>),
      mysql:execute(dns_pool, select_records, [Qname]);
    ?DNS_TYPE_A_BSTR ->
      mysql:prepare(select_records_of_a_type, <<"select * from records where name = ? and (type = ? or type = ?)">>),
      mysql:execute(dns_pool, select_records_of_a_type, [Qname, Qtype, <<"CNAME">>]);
    _ ->
      mysql:prepare(select_records_of_type, <<"select * from records where name = ? and type = ?">>),
      mysql:execute(dns_pool, select_records_of_type, [Qname, Qtype])
  end,
  lager:debug("~p:lookup found rows~n", [?MODULE]),
  Data#mysql_result.rows.

resolve_cnames(Records) ->
  [resolve_cname(Record) || Record <- Records].

resolve_cname(Record) ->
  lager:debug("~p:resolve_cname(~p)~n", [?MODULE, Record]),
  case Record#dns_rr.type of
    ?DNS_TYPE_CNAME_NUMBER ->
      [Qname, Qtype] = [Record#dns_rr.data#dns_rrdata_cname.dname, ?DNS_TYPE_A_BSTR],
      lists:map(fun row_to_record/1, lookup(Qname, Qtype)) ++ [Record];
    _ ->
      Record
  end.


row_to_record(Row) ->
  [_, _Id, Name, TypeStr, Content, TTL, Priority, _ChangeDate] = Row,
  case parse_content(Content, Priority, TypeStr) of
    unsupported -> [];
    Data -> #dns_rr{name=Name, type=erldns_records:name_type(TypeStr), data=Data, ttl=TTL}
  end.

%% All of these functions are used to parse the content field
%% stored in MySQL into a correct dns_rrdata in-memory record.
parse_content(Content, _, ?DNS_TYPE_SOA_BSTR) ->
  [MnameStr, RnameStr, SerialStr, RefreshStr, RetryStr, ExpireStr, MinimumStr] = string:tokens(binary_to_list(Content), " "),
  [Mname, Rname, Serial, Refresh, Retry, Expire, Minimum] =
    [MnameStr, RnameStr, to_i(SerialStr), to_i(RefreshStr), to_i(RetryStr), to_i(ExpireStr), to_i(MinimumStr)],
  #dns_rrdata_soa{mname=Mname, rname=Rname, serial=Serial, refresh=Refresh, retry=Retry, expire=Expire, minimum=Minimum};

parse_content(Content, _, ?DNS_TYPE_NS_BSTR) ->
  #dns_rrdata_ns{dname=Content};
parse_content(Content, _, ?DNS_TYPE_CNAME_BSTR) ->
  #dns_rrdata_cname{dname=Content};
parse_content(Content, _, ?DNS_TYPE_PTR_BSTR) ->
  #dns_rrdata_ptr{dname=Content};

parse_content(Content, _, ?DNS_TYPE_A_BSTR) ->
  {ok, Address} = inet_parse:address(binary_to_list(Content)),
  #dns_rrdata_a{ip=Address};
parse_content(Content, _, ?DNS_TYPE_AAAA_BSTR) ->
  {ok, Address} = inet_parse:address(binary_to_list(Content)),
  #dns_rrdata_aaaa{ip=Address};

parse_content(Content, Priority, ?DNS_TYPE_MX_BSTR) ->
  #dns_rrdata_mx{exchange=Content, preference=Priority};

parse_content(Content, _, ?DNS_TYPE_TXT_BSTR) ->
  #dns_rrdata_txt{txt=binary_to_list(Content)};
parse_content(Content, _, ?DNS_TYPE_SPF_BSTR) ->
  #dns_rrdata_spf{spf=binary_to_list(Content)};

parse_content(Content, Priority, ?DNS_TYPE_SRV_BSTR) ->
  [WeightStr, PortStr, Target] = string:tokens(binary_to_list(Content), " "),
  #dns_rrdata_srv{priority=Priority, weight=to_i(WeightStr), port=to_i(PortStr), target=Target};

parse_content(Content, _, ?DNS_TYPE_NAPTR_BSTR) ->
  [OrderStr, PreferenceStr, FlagsStr, ServicesStr, RegexpStr, ReplacementStr] = string:tokens(binary_to_list(Content), " "),
  #dns_rrdata_naptr{order=to_i(OrderStr), preference=to_i(PreferenceStr), flags=list_to_binary(string:strip(FlagsStr, both, $")), services=list_to_binary(string:strip(ServicesStr, both, $")), regexp=list_to_binary(string:strip(RegexpStr, both, $")), replacement=list_to_binary(ReplacementStr)};

parse_content(Content, _, ?DNS_TYPE_SSHFP_BSTR) ->
  [AlgStr, FpTypeStr, FpStr] = string:tokens(binary_to_list(Content), " "),
  #dns_rrdata_sshfp{alg=to_i(AlgStr), fp_type=to_i(FpTypeStr), fp=list_to_binary(FpStr)};

parse_content(Content, _, ?DNS_TYPE_RP_BSTR) ->
  [Mbox, Txt] = string:tokens(binary_to_list(Content), " "),
  #dns_rrdata_rp{mbox=Mbox, txt=Txt};

parse_content(Content, _, ?DNS_TYPE_HINFO_BSTR) ->
  [Cpu, Os] = string:tokens(binary_to_list(Content), " "),
  #dns_rrdata_hinfo{cpu=Cpu, os=Os};

parse_content(Content, _, ?DNS_TYPE_AFSDB_BSTR) ->
  [SubtypeStr, Hostname] = string:tokens(binary_to_list(Content), " "),
  #dns_rrdata_afsdb{subtype = to_i(SubtypeStr), hostname = Hostname};

parse_content(_, _, Type) ->
  lager:warning("Unsupported record type: ~p", [Type]),
  unsupported.


%% Utility method for converting a string to an integer.
to_i(Str) ->
  {Int, _} = string:to_integer(Str), Int.
