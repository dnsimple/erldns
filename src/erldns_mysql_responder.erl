-module(erldns_mysql_responder).

-include("deps/dns/include/dns.hrl").
-include("deps/mysql/include/mysql.hrl").

-export([answer/2]).

answer(Qname, Qtype) ->
  lists:map(
    fun(Row) ->
      [_, _Id, Name, TypeStr, Content, TTL, Priority, _ChangeDate] = Row,
      #dns_rr{name=Name, type=name_type(TypeStr), data=parse_content(Content, Priority, TypeStr), ttl=TTL}
    end, lookup(Qname, Qtype)
  ).

lookup(Qname, Qtype) ->
  {data, Data} = case Qtype of
    <<"ANY">> ->
      mysql:prepare(select_records, <<"select * from records where name = ?">>),
      mysql:execute(dns_pool, select_records, [Qname]);
    _ ->
      mysql:prepare(select_records_of_type, <<"select * from records where name = ? and type = ?">>),
      mysql:execute(dns_pool, select_records_of_type, [Qname, Qtype])
  end,
  Data#mysql_result.rows.

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

parse_content(Content, _Priority, _Type) ->
  Content.


%% Utility method for converting a string to an integer.
to_i(Str) ->
  {Int, _} = string:to_integer(Str),
  Int.

%% @doc Returns the type value given a binary string.
-spec name_type(binary()) -> dns:type() | 'undefined'.
name_type(Type) when is_binary(Type) ->
    case Type of
	?DNS_TYPE_A_BSTR -> ?DNS_TYPE_A_NUMBER;
	?DNS_TYPE_NS_BSTR -> ?DNS_TYPE_NS_NUMBER;
	?DNS_TYPE_MD_BSTR -> ?DNS_TYPE_MD_NUMBER;
	?DNS_TYPE_MF_BSTR -> ?DNS_TYPE_MF_NUMBER;
        ?DNS_TYPE_CNAME_BSTR -> ?DNS_TYPE_CNAME_NUMBER;
	?DNS_TYPE_SOA_BSTR -> ?DNS_TYPE_SOA_NUMBER;
        ?DNS_TYPE_MB_BSTR -> ?DNS_TYPE_MB_NUMBER;
        ?DNS_TYPE_MG_BSTR -> ?DNS_TYPE_MG_NUMBER;
        ?DNS_TYPE_MR_BSTR -> ?DNS_TYPE_MR_NUMBER;
        ?DNS_TYPE_NULL_BSTR -> ?DNS_TYPE_NULL_NUMBER;
        ?DNS_TYPE_WKS_BSTR -> ?DNS_TYPE_WKS_NUMBER;
        ?DNS_TYPE_PTR_BSTR -> ?DNS_TYPE_PTR_NUMBER;
        ?DNS_TYPE_HINFO_BSTR -> ?DNS_TYPE_HINFO_NUMBER;
        ?DNS_TYPE_MINFO_BSTR -> ?DNS_TYPE_MINFO_NUMBER;
        ?DNS_TYPE_MX_BSTR -> ?DNS_TYPE_MX_NUMBER;
        ?DNS_TYPE_TXT_BSTR -> ?DNS_TYPE_TXT_NUMBER;
        ?DNS_TYPE_RP_BSTR -> ?DNS_TYPE_RP_NUMBER;
        ?DNS_TYPE_AFSDB_BSTR -> ?DNS_TYPE_AFSDB_NUMBER;
        ?DNS_TYPE_X25_BSTR -> ?DNS_TYPE_X25_NUMBER;
        ?DNS_TYPE_ISDN_BSTR -> ?DNS_TYPE_ISDN_NUMBER;
        ?DNS_TYPE_RT_BSTR -> ?DNS_TYPE_RT_NUMBER;
        ?DNS_TYPE_NSAP_BSTR -> ?DNS_TYPE_NSAP_NUMBER;
        ?DNS_TYPE_SIG_BSTR -> ?DNS_TYPE_SIG_NUMBER;
        ?DNS_TYPE_KEY_BSTR -> ?DNS_TYPE_KEY_NUMBER;
        ?DNS_TYPE_PX_BSTR -> ?DNS_TYPE_PX_NUMBER;
        ?DNS_TYPE_GPOS_BSTR -> ?DNS_TYPE_GPOS_NUMBER;
        ?DNS_TYPE_AAAA_BSTR -> ?DNS_TYPE_AAAA_NUMBER;
        ?DNS_TYPE_LOC_BSTR -> ?DNS_TYPE_LOC_NUMBER;
        ?DNS_TYPE_NXT_BSTR -> ?DNS_TYPE_NXT_NUMBER;
        ?DNS_TYPE_EID_BSTR -> ?DNS_TYPE_EID_NUMBER;
        ?DNS_TYPE_NIMLOC_BSTR -> ?DNS_TYPE_NIMLOC_NUMBER;
        ?DNS_TYPE_SRV_BSTR -> ?DNS_TYPE_SRV_NUMBER;
        ?DNS_TYPE_ATMA_BSTR -> ?DNS_TYPE_ATMA_NUMBER;
        ?DNS_TYPE_NAPTR_BSTR -> ?DNS_TYPE_NAPTR_NUMBER;
        ?DNS_TYPE_KX_BSTR -> ?DNS_TYPE_KX_NUMBER;
        ?DNS_TYPE_CERT_BSTR -> ?DNS_TYPE_CERT_NUMBER;
        ?DNS_TYPE_DNAME_BSTR -> ?DNS_TYPE_DNAME_NUMBER;
        ?DNS_TYPE_SINK_BSTR -> ?DNS_TYPE_SINK_NUMBER;
        ?DNS_TYPE_OPT_BSTR -> ?DNS_TYPE_OPT_NUMBER;
        ?DNS_TYPE_APL_BSTR -> ?DNS_TYPE_APL_NUMBER;
        ?DNS_TYPE_DS_BSTR -> ?DNS_TYPE_DS_NUMBER;
        ?DNS_TYPE_SSHFP_BSTR -> ?DNS_TYPE_SSHFP_NUMBER;
        ?DNS_TYPE_IPSECKEY_BSTR -> ?DNS_TYPE_IPSECKEY_NUMBER;
        ?DNS_TYPE_RRSIG_BSTR -> ?DNS_TYPE_RRSIG_NUMBER;
        ?DNS_TYPE_NSEC_BSTR -> ?DNS_TYPE_NSEC_NUMBER;
        ?DNS_TYPE_DNSKEY_BSTR -> ?DNS_TYPE_DNSKEY_NUMBER;
        ?DNS_TYPE_NSEC3_BSTR -> ?DNS_TYPE_NSEC3_NUMBER;
        ?DNS_TYPE_NSEC3PARAM_BSTR -> ?DNS_TYPE_NSEC3PARAM_NUMBER;
        ?DNS_TYPE_DHCID_BSTR -> ?DNS_TYPE_DHCID_NUMBER;
        ?DNS_TYPE_HIP_BSTR -> ?DNS_TYPE_HIP_NUMBER;
        ?DNS_TYPE_NINFO_BSTR -> ?DNS_TYPE_NINFO_NUMBER;
        ?DNS_TYPE_RKEY_BSTR -> ?DNS_TYPE_RKEY_NUMBER;
        ?DNS_TYPE_TALINK_BSTR -> ?DNS_TYPE_TALINK_NUMBER;
        ?DNS_TYPE_SPF_BSTR -> ?DNS_TYPE_SPF_NUMBER;
        ?DNS_TYPE_UINFO_BSTR -> ?DNS_TYPE_UINFO_NUMBER;
        ?DNS_TYPE_UID_BSTR -> ?DNS_TYPE_UID_NUMBER;
        ?DNS_TYPE_GID_BSTR -> ?DNS_TYPE_GID_NUMBER;
        ?DNS_TYPE_UNSPEC_BSTR -> ?DNS_TYPE_UNSPEC_NUMBER;
        ?DNS_TYPE_TKEY_BSTR -> ?DNS_TYPE_TKEY_NUMBER;
        ?DNS_TYPE_TSIG_BSTR -> ?DNS_TYPE_TSIG_NUMBER;
        ?DNS_TYPE_IXFR_BSTR -> ?DNS_TYPE_IXFR_NUMBER;
        ?DNS_TYPE_AXFR_BSTR -> ?DNS_TYPE_AXFR_NUMBER;
        ?DNS_TYPE_MAILB_BSTR -> ?DNS_TYPE_MAILB_NUMBER;
        ?DNS_TYPE_MAILA_BSTR -> ?DNS_TYPE_MAILA_NUMBER;
        ?DNS_TYPE_ANY_BSTR -> ?DNS_TYPE_ANY_NUMBER;
        ?DNS_TYPE_DLV_BSTR -> ?DNS_TYPE_DLV_NUMBER;
	_ -> undefined
    end.
