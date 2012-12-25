-module(erldns_pgsql).

-include("dns.hrl").
-include("erldns.hrl").

-export([init/0, lookup_records/0, domain_names/1]).
-export([db_to_record/2]).

-define(MAX_TXT_SIZE, 255).

init() -> ok.

lookup_records() ->
  case squery("select * from domains") of
    {ok, _, Rows} ->
      lists:map(
        fun({Id,Name,_,_,_,_,_}) ->
            {Name, lookup_records(Name, list_to_integer(binary_to_list(Id)))}
        end, Rows);
    Result ->
      lager:error("~p:~p", [?MODULE, Result]), []
  end.

lookup_records(Name, DomainId) ->
  case equery("select * from records where domain_id = $1", [DomainId]) of
    {ok, _, Rows} ->
      lists:map(fun(Row) -> row_to_record(Name, Row) end, Rows);
    Result ->
      lager:error("~p:~p", [?MODULE, Result]), []
  end.

%% Convert a name to a list of possible domain names by working
%% back through the labels to construct each possible domain.
domain_names(Qname) -> domain_names(dns:dname_to_labels(Qname), []).
domain_names([], Names) -> Names;
domain_names([Label|Rest], Names) -> domain_names(Rest, Names ++ [dns:labels_to_dname([Label] ++ Rest)]).

%% Take a row and turn it into a DNS resource record.
row_to_record(_, {_, _Id, Name, Type, Content, TTL, Priority, _ChangeDate}) ->
  #db_rr{name=Name, type=Type, content=Content, ttl=TTL, priority=Priority};
row_to_record(_, {_, _Id, Name, Type, Content, TTL, Priority, _ChangeDate, _Auth}) ->
  #db_rr{name=Name, type=Type, content=Content, ttl=TTL, priority=Priority}.

%% Convert an internal DB representation to a dns RR.
db_to_record(Qname, Record) when is_record(Record, db_rr) ->
  lager:debug("Parsing content for ~p", [Qname]),
  case parse_content(Record#db_rr.content, Record#db_rr.priority, Record#db_rr.type) of
    unsupported -> unsupported;
    Data ->
      #dns_rr{
        name = Record#db_rr.name,
        type = erldns_records:name_type(Record#db_rr.type),
        data = Data,
        ttl  = erldns_records:default_ttl(Record#db_rr.ttl)
      }
  end;
db_to_record(Qname, Value) ->
  lager:debug("~p:failed to convert DB record to DNS record for ~p with ~p (wildcard? ~p)", [?MODULE, Qname, Value]),
  [].

%% All of these functions are used to parse the content field
%% stored in the DB into a correct dns_rrdata in-memory record.
parse_content(Content, _, ?DNS_TYPE_SOA_BSTR) ->
  case string:tokens(binary_to_list(Content), " ") of
    [MnameStr, RnameStr, SerialStr, RefreshStr, RetryStr, ExpireStr, MinimumStr] ->
      [Mname, Rname, Serial, Refresh, Retry, Expire, Minimum] = [MnameStr, re:replace(RnameStr, "@", ".", [{return, list}]), to_i(SerialStr), to_i(RefreshStr), to_i(RetryStr), to_i(ExpireStr), to_i(MinimumStr)],
      #dns_rrdata_soa{mname=Mname, rname=Rname, serial=Serial, refresh=Refresh, retry=Retry, expire=Expire, minimum=Minimum};
    _ ->
      lager:error("~p:SOA record with invalid content: ~p", [?MODULE, Content]),
      unsupported
  end;

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
  #dns_rrdata_mx{exchange=Content, preference=erldns_records:default_priority(Priority)};

parse_content(Content, _, ?DNS_TYPE_SPF_BSTR) ->
  #dns_rrdata_spf{spf=binary_to_list(Content)};

parse_content(Content, Priority, ?DNS_TYPE_SRV_BSTR) ->
  [WeightStr, PortStr, Target] = string:tokens(binary_to_list(Content), " "),
  #dns_rrdata_srv{priority=erldns_records:default_priority(Priority), weight=to_i(WeightStr), port=to_i(PortStr), target=Target};

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

% TODO: this does not properly encode yet.
parse_content(Content, _, ?DNS_TYPE_LOC_BSTR) ->
  % 51 56 0.123 N 5 54 0.000 E 4.00m 1.00m 10000.00m 10.00m
  [DegLat, MinLat, SecLat, _DirLat, DegLon, MinLon, SecLon, _DirLon, AltStr, SizeStr, HorizontalStr, VerticalStr] = string:tokens(binary_to_list(Content), " "),
  Alt = to_i(string:strip(AltStr, right, $m)),
  Size = list_to_float(string:strip(SizeStr, right, $m)),
  Horizontal = list_to_float(string:strip(HorizontalStr, right, $m)),
  Vertical = list_to_float(string:strip(VerticalStr, right, $m)),
  Lat = to_i(DegLat) + to_i(MinLat) / 60 + to_i(SecLat) / 3600,
  Lon = to_i(DegLon) + to_i(MinLon) / 60 + to_i(SecLon) / 3600,
  #dns_rrdata_loc{lat=Lat, lon=Lon, alt=Alt, size=Size, horiz=Horizontal, vert=Vertical};

parse_content(Content, _, ?DNS_TYPE_AFSDB_BSTR) ->
  [SubtypeStr, Hostname] = string:tokens(binary_to_list(Content), " "),
  #dns_rrdata_afsdb{subtype = to_i(SubtypeStr), hostname = Hostname};

parse_content(Content, _, ?DNS_TYPE_TXT_BSTR) ->
  #dns_rrdata_txt{txt=lists:flatten(parse_txt(binary_to_list(Content)))};

parse_content(_, _, Type) ->
  lager:debug("Unsupported record type: ~p", [Type]),
  unsupported.

parse_txt([C|Rest]) -> parse_txt_char([C|Rest], C, Rest, [], false).
parse_txt(String, [], [], _) -> [split_txt(String)];
parse_txt(_, [], Tokens, _) -> Tokens;
parse_txt(String, [C|Rest], Tokens, Escaped) -> parse_txt_char(String, C, Rest, Tokens, Escaped).
parse_txt(String, [C|Rest], Tokens, CurrentToken, Escaped) -> parse_txt_char(String, C, Rest, Tokens, CurrentToken, Escaped).
parse_txt_char(String, $", Rest, Tokens, _) -> parse_txt(String, Rest, Tokens, [], false);
parse_txt_char(String, _, Rest, Tokens, _) -> parse_txt(String, Rest, Tokens, false).
parse_txt_char(String, $", Rest, Tokens, CurrentToken, false) -> parse_txt(String, Rest, Tokens ++ [split_txt(CurrentToken)], false);
parse_txt_char(String, $", Rest, Tokens, CurrentToken, true) -> parse_txt(String, Rest, Tokens, CurrentToken ++ [$"], false);
parse_txt_char(String, $\\, Rest, Tokens, CurrentToken, false) -> parse_txt(String, Rest, Tokens, CurrentToken, true);
parse_txt_char(String, $\\, Rest, Tokens, CurrentToken, true) -> parse_txt(String, Rest, Tokens, CurrentToken ++ [$\\], false);
parse_txt_char(String, C, Rest, Tokens, CurrentToken, _) -> parse_txt(String, Rest, Tokens, CurrentToken ++ [C], false).

split_txt(Data) -> split_txt(Data, []).
split_txt(Data, Parts) ->
  case byte_size(list_to_binary(Data)) > ?MAX_TXT_SIZE of
    true ->
      First = list_to_binary(string:substr(Data, 1, ?MAX_TXT_SIZE)),
      Rest = string:substr(Data, ?MAX_TXT_SIZE + 1),
      case Rest of
        [] -> Parts ++ [First];
        _ -> split_txt(Rest, Parts ++ [First])
      end;
    false ->
      Parts ++ [list_to_binary(Data)]
  end.

%% Utility method for converting a string to an integer.
to_i(Str) -> {Int, _} = string:to_integer(Str), Int.

squery(Stmt) -> squery(pgsql_pool, Stmt).
squery(PoolName, Stmt) ->
  poolboy:transaction(PoolName,
    fun(Worker) ->
        gen_server:call(Worker, {squery, Stmt})
    end).

equery(Stmt, Params) -> equery(pgsql_pool, Stmt, Params).
equery(PoolName, Stmt, Params) ->
  poolboy:transaction(PoolName,
    fun(Worker) ->
        gen_server:call(Worker, {equery, Stmt, Params})
    end).
  

