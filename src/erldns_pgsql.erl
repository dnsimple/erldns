-module(erldns_pgsql).

-include("dns.hrl").
-include("erldns.hrl").

-export([init/0, lookup_records/0, domain_names/1]).

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
  lager:info("lookup_records(~p, ~p)", [Name, DomainId]),
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

% Internal API
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
  

