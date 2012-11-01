-module(erldns_mysql_responder).

-include("dns.hrl").
-include("mysql.hrl").
-include("erldns.hrl").

-export([answer/2, get_soa/1, get_metadata/1]).

%% Get the SOA record for the name.
get_soa(Qname) -> lookup_soa(Qname).

%% Get the metadata for the name.
get_metadata(Qname) -> erldns_mysql:get_metadata(Qname).

%% Answer the given question for the given name.
answer(Qname, Qtype) ->
  lager:debug("~p:answer(~p, ~p)", [?MODULE, Qname, Qtype]),
  lists:flatten(
    folsom_metrics:histogram_timed_update(
      mysql_responder_lookup_time, fun lookup/2, [Qname, Qtype]
    )
  ).

%% Lookup a specific name and type and convert it into a list of DNS records.
%% First a non-wildcard lookup will occur and if there are results those will
%% be used. If no results are found then a wildcard lookup is attempted.
lookup(Qname, Qtype) ->
  Answers = lookup_name(Qname, Qtype, Qname),
  case Answers of
    [] -> lookup_name(Qname, Qtype, erldns_mysql:wildcard_qname(Qname));
    _ -> Answers
  end.

%% Lookup the record with the given name and type. The LookupName should
%% be the value expected in the database (which may be a wildcard).
lookup_name(Qname, Qtype, LookupName) ->
  lists:map(fun(RR) -> mysql_to_record(Qname, RR) end, erldns_mysql:lookup_name(Qname, Qtype, LookupName)). 

%% Lookup the SOA record for a given name.
lookup_soa(Qname) -> mysql_to_record(Qname, erldns_mysql:lookup_soa(Qname)).

%% Convert an internal MySQL representation to a dns RR.
mysql_to_record(Qname, Record) ->
  lager:debug("~p:mysql_to_record(~p, ~p)", [?MODULE, Qname, Record]),
  case parse_content(Record#mysql_rr.content, Record#mysql_rr.priority, Record#mysql_rr.type) of
    unsupported -> [];
    Data -> #dns_rr{name=erldns_mysql:optionally_convert_wildcard(Record#mysql_rr.name, Qname), type=erldns_records:name_type(Record#mysql_rr.type), data=Data, ttl=default_ttl(Record#mysql_rr.ttl)}
  end.

%% All of these functions are used to parse the content field
%% stored in MySQL into a correct dns_rrdata in-memory record.
parse_content(Content, _, ?DNS_TYPE_SOA_BSTR) ->
  [MnameStr, RnameStr, SerialStr, RefreshStr, RetryStr, ExpireStr, MinimumStr] = string:tokens(binary_to_list(Content), " "),
  [Mname, Rname, Serial, Refresh, Retry, Expire, Minimum] = [MnameStr, re:replace(RnameStr, "@", ".", [{return, list}]), to_i(SerialStr), to_i(RefreshStr), to_i(RetryStr), to_i(ExpireStr), to_i(MinimumStr)],
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
  #dns_rrdata_mx{exchange=Content, preference=default_priority(Priority)};

parse_content(Content, _, ?DNS_TYPE_TXT_BSTR) ->
  #dns_rrdata_txt{txt=binary_to_list(Content)};
parse_content(Content, _, ?DNS_TYPE_SPF_BSTR) ->
  #dns_rrdata_spf{spf=binary_to_list(Content)};

parse_content(Content, Priority, ?DNS_TYPE_SRV_BSTR) ->
  [WeightStr, PortStr, Target] = string:tokens(binary_to_list(Content), " "),
  #dns_rrdata_srv{priority=default_priority(Priority), weight=to_i(WeightStr), port=to_i(PortStr), target=Target};

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
  lager:debug("Mysql responder unsupported record type: ~p", [Type]),
  unsupported.


%% Utility method for converting a string to an integer.
to_i(Str) -> {Int, _} = string:to_integer(Str), Int.

%% Return the TTL value or 3600 if it is undefined.
default_ttl(TTL) ->
  case TTL of
    undefined -> 3600;
    Value -> Value
  end.

%% Return the Priority value or 0 if it is undefined.
default_priority(Priority) ->
  case Priority of
    undefined -> 0;
    Value -> Value
  end.
