-module(erldns_mysql).

-include("mysql.hrl").

-export([safe_mysql_handler/2, optionally_convert_wildcard/2, wildcard_qname/1]).

%% Wrap MySQL response handling so errors are handled in a consistent
%% fashion. The function F will be executed upon success.
safe_mysql_handler(Response, F) ->
  case Response of
    {data, Data} -> F(Data);
    {error, Data} ->
      lager:error("~p:~p", [?MODULE, Data#mysql_result.error]),
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
