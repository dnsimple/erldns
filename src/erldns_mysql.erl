-module(erldns_mysql).

-include("dns.hrl").
-include("mysql.hrl").
-include("erldns.hrl").

-export([init/0, lookup_name/3, lookup_ns_records/1, lookup_records/1, lookup_soa/1, get_metadata/1, domain_names/1]).
-export([safe_mysql_handler/2, optionally_convert_wildcard/2, wildcard_qname/1]).

% Prepare all statements.
init() ->
  mysql:prepare(select_axfr, <<"select records.* from domains join records on domains.id = records.domain_id where domains.name = ?">>),
  mysql:prepare(select_records, <<"select * from records where name = ?">>),
  mysql:prepare(select_records_of_type, <<"select * from records where name = ? and (type = ? or type = ?)">>),
  mysql:prepare(select_domainmetadata, <<"select domainmetadata.* from domains join domainmetadata on domains.id = domainmetadata.domain_id where domains.id = (select records.domain_id from records where name = ? limit 1)">>).

lookup_ns_records(Qname) ->
  lists:filter(fun(R) -> (R#mysql_rr.name =:= Qname) and (R#mysql_rr.type =:= <<"NS">>) end, lookup_records(Qname)).

lookup_soa(Qname) ->
  lager:debug("~p:lookup_soa(~p)", [?MODULE, Qname]),
  DomainNames = domain_names(Qname),
  lager:debug("~p:domain names: ~p", [?MODULE, DomainNames]),
  % I feel this is an ok use of list_to_atom because there are only a small number of possible atom names.
  QueryName = list_to_atom("select_soa" ++ integer_to_list(length(DomainNames))),
  mysql:prepare(QueryName, build_soa_query(DomainNames)),
  erldns_mysql:safe_mysql_handler(mysql:execute(dns_pool, QueryName, lists:flatten([DomainNames, <<"SOA">>])),
    fun(Data) ->
        case Data#mysql_result.rows of
          [] -> [];
          [SoaRecord] -> row_to_record(Qname, SoaRecord);
          [SoaRecord|_] -> row_to_record(Qname, SoaRecord)
        end
    end).

%% This is a hack because the mysql driver cannot encode lists
%% for use in queries like "foo IN (?)"
build_soa_query(DomainNames) ->
  list_to_binary(["select records.* from domains join records on domains.id = records.domain_id where domains.id = (select records.domain_id from records where "] ++ string:join(lists:map(fun(_) -> "name = ?" end, DomainNames), " or ") ++ [" limit 1) and records.type = ? limit 1"]).

%% Lookup all records for a given Qname.
lookup_records(Qname) ->
  DomainNames = domain_names(Qname),
  QueryName = list_to_atom("select_domain_records" ++ integer_to_list(length(DomainNames))),
  mysql:prepare(QueryName, build_domain_records_query(DomainNames)),
  erldns_mysql:safe_mysql_handler(mysql:execute(dns_pool, QueryName, DomainNames),
    fun(Data) ->
        lists:map(fun(Row) -> row_to_record(Qname, Row) end, Data#mysql_result.rows)
    end).

%% This is a hack because the mysql driver cannot encode lists
%% for use in queries like "foo IN (?)"
build_domain_records_query(DomainNames) ->
  list_to_binary(["select records.* from domains join records on domains.id = records.domain_id where domains.id = (select records.domain_id from records where "] ++ string:join(lists:map(fun(_) -> "name = ?" end, DomainNames), " or ") ++ [" limit 1)"]).

%% Lookup a name of a particular type.
lookup_name(Qname, Qtype, LookupName) ->
  lager:debug("~p:lookup_name(~p, ~p, ~p)", [?MODULE, Qname, Qtype, LookupName]),
  erldns_mysql:safe_mysql_handler(case Qtype of
    ?DNS_TYPE_AXFR_BSTR ->
      mysql:execute(dns_pool, select_axfr, [Qname]);
    ?DNS_TYPE_ANY_BSTR ->
      mysql:execute(dns_pool, select_records, [LookupName]);
    _ ->
      mysql:execute(dns_pool, select_records_of_type, [LookupName, Qtype, <<"CNAME">>])
  end, fun(Data) -> lists:map(fun(Row) -> row_to_record(Qname, Row) end, Data#mysql_result.rows) end).

%% Convert a name to a list of possible domain names by working
%% back through the labels to construct each possible domain.
domain_names(Qname) -> domain_names(dns:dname_to_labels(Qname), []).
domain_names([], Names) -> Names;
domain_names([Label|Rest], Names) -> domain_names(Rest, Names ++ [dns:labels_to_dname([Label] ++ Rest)]).

%% Take a MySQL row and turn it into a DNS resource record.
row_to_record(_, Row) ->
  [_, _Id, Name, Type, Content, TTL, Priority, _ChangeDate] = Row,
  #mysql_rr{name=Name, type=Type, content=Content, ttl=TTL, priority=Priority}.

%% Get the metadata for the name.
get_metadata(Qname) ->
  safe_mysql_handler(mysql:execute(dns_pool, select_domainmetadata, [Qname]),
    fun(Data) -> Data#mysql_result.rows end
  ).

%% Wrap MySQL response handling so errors are handled in a consistent
%% fashion. The function F will be executed upon success.
safe_mysql_handler(Response, F) ->
  case Response of
    {data, Data} -> F(Data);
    {error, Data} ->
      lager:error("~p:~p", [?MODULE, Data]),
      []
  end.

%% If the name returned from the DB is a wildcard name then the
%% Original Qname needs to be returned in its place.
optionally_convert_wildcard(Name, Qname) ->
  [Head|_] = dns:dname_to_labels(Name),
  case Head of
    <<"*">> -> Qname;
    _ -> Name
  end.

%% Get a wildcard variation of a Qname. Replaces the leading
%% label with an asterisk for wildcard lookup.
wildcard_qname(Qname) ->
  [_|Rest] = dns:dname_to_labels(Qname),
  dns:labels_to_dname([<<"*">>] ++ Rest).
