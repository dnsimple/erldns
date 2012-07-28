-module(erldns_mysql_responder).
-include("include/nsrecs.hrl").
-export([answer/1]).
-on_load(init/0).

-define(POOL_ID, erldns_mysql_responder).

init() ->
  [PoolId, Host, User, Password, Database] = [?POOL_ID, "localhost", "root", "", "powerdns"],
  mysql:start_link(PoolId, Host, User, Password, Database).

answer(_Questions) ->
  [].
