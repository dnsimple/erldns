-module(erldns_config).

-export([get_address/1, get_port/0]).

-define(DEFAULT_IPV4_ADDRESS, {127,0,0,1}).
-define(DEFAULT_IPV6_ADDRESS, {0,0,0,0,0,0,0,1}).
-define(DEFAULT_PORT, 53).

%% Private functions
get_address(inet) ->
  case application:get_env(erldns, inet4) of
    {ok, Address} -> parse_address(Address);
    _ -> ?DEFAULT_IPV4_ADDRESS
  end;
get_address(inet6) ->
  case application:get_env(erldns, inet6) of
    {ok, Address} -> parse_address(Address);
    _ -> ?DEFAULT_IPV6_ADDRESS
  end.

get_port() ->
  case application:get_env(erldns, port) of
    {ok, Port} -> Port;
    _ -> ?DEFAULT_PORT
  end.

parse_address(Address) when is_list(Address) ->
  {ok, Tuple} = inet_parse:address(Address), Tuple;
parse_address(Address) -> Address.
