-module(erldns_pgsql).

-include("dns.hrl").
-include("erldns.hrl").

-export([init/0, lookup_name/3, lookup_records/1, lookup_soa/1, get_metadata/1, domain_names/1, equery/2, equery/3]).

init() -> ok.

lookup_soa(Qname) ->
  DomainNames = domain_names(Qname),
  case equery(pgsql_pool, build_soa_query(DomainNames), lists:flatten([DomainNames, <<"SOA">>])) of
    {ok, _, []} -> [];
    {ok, _, [Row]} -> row_to_record(Qname, Row);
    {ok, _, [Row|_]} -> row_to_record(Qname, Row);
    Result ->
      lager:error("~p:~p", [?MODULE, Result]), []
  end.

%% This is a hack because the PostgreSQL driver cannot encode lists
%% for use in queries like "foo IN (?)"
build_soa_query(DomainNames) ->
  {WhereClause, NextIndex} = build_domain_list_clause(DomainNames), 
  PostWhereClause = lists:concat([" limit 1) and records.type = $", NextIndex, " limit 1"]),
  list_to_binary(["select records.* from domains join records on domains.id = records.domain_id where domains.id = (select records.domain_id from records where "] ++ [WhereClause, PostWhereClause]).

lookup_records(Qname) -> 
  DomainNames = domain_names(Qname),
  Records = case equery(build_domain_records_query(DomainNames), DomainNames) of
    {ok, _, Rows} ->
      lists:map(fun(Row) -> row_to_record(Qname, Row) end, Rows);
    Result ->
      lager:error("~p:~p", [?MODULE, Result]), []
  end,
  %lager:info("lookup_records(~p): ~p", [Qname, Records]),
  Records.

build_domain_records_query(DomainNames) ->
  {WhereClause, _} = build_domain_list_clause(DomainNames),
  list_to_binary(["select records.* from domains join records on domains.id = records.domain_id where domains.id = (select records.domain_id from records where "] ++ [WhereClause, " limit 1)"]).

lookup_name(Qname, Qtype, LookupName) ->
  lager:debug("~p:lookup_name(~p, ~p, ~p)", [?MODULE, Qname, Qtype, LookupName]),
  QueryResult = case Qtype of
    ?DNS_TYPE_AXFR_BSTR ->
      equery(<<"select records.* from domains join records on domains.id = records.domain_id where lower(domains.name) = $1">>, [Qname]);
    ?DNS_TYPE_ANY_BSTR ->
      equery(<<"select * from records where lower(name) = $1">> , [LookupName]);
    _ ->
      equery(pgsql_pool, <<"select * from records where lower(name) = $1 and type = $2">>, [LookupName, Qtype])
  end,
  case QueryResult of
    {ok, _, Rows} ->
      lists:map(fun(Row) -> row_to_record(Qname, Row) end, Rows);
    Result ->
      lager:error("~p:~p", [?MODULE, Result]), []
  end.

get_metadata(Qname) -> 
  case equery(<<"select domainmetadata.* from domains join domainmetadata on domains.id = domainmetadata.domain_id where domains.id = (select records.domain_id from records where lower(name) = $1 limit 1)">>, [Qname]) of
    {ok, _, Rows} -> Rows
  end.

%% Given a list of domain names, build an OR-separated SQL where
%% clause with the appropriate placeholders. Return the result
%% as the tuple {WhereClause, NextIndex}.
build_domain_list_clause(DomainNames) ->
  build_domain_list_clause(DomainNames, 1).
build_domain_list_clause(DomainNames, Offset) ->
  build_domain_list_clause(DomainNames, Offset, []).
build_domain_list_clause([], Index, Clauses) ->
  {string:join(Clauses, " or "), Index};
build_domain_list_clause([_|Rest], Index, Clauses) ->
  build_domain_list_clause(Rest, Index + 1, Clauses ++ [lists:concat(["lower(name) = $", Index])]).

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

% Internal API
equery(Stmt, Params) -> equery(pgsql_pool, Stmt, Params).
equery(PoolName, Stmt, Params) ->
  poolboy:transaction(PoolName, fun(Worker) ->
      gen_server:call(Worker, {equery, Stmt, Params})
  end).
  

