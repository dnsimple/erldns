%% Copyright (c) 2012-2014, Aetrion LLC
%%
%% Permission to use, copy, modify, and/or distribute this software for any
%% purpose with or without fee is hereby granted, provided that the above
%% copyright notice and this permission notice appear in all copies.
%%
%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
%% WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
%% MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
%% ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
%% WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
%% ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
%% OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

%% @doc Provide application-wide configuration access.
-module(erldns_config).

-export([
         get_server_configs/0,
         get_address/1,
         get_port/0,
         get_num_workers/0
        ]).
-export([
         use_root_hints/0
        ]).
-export([
         zone_server_env/0,
         zone_server_max_processes/0,
         zone_server_protocol/0,
         zone_server_host/0,
         zone_server_port/0
        ]).
-export([
         websocket_env/0,
         websocket_protocol/0,
         websocket_host/0,
         websocket_port/0,
         websocket_path/0,
         websocket_url/0
        ]).
-export([
         storage_env/0,
         storage_type/0,
         storage_user/0,
         storage_pass/0,
         storage_host/0,
         storage_port/0,
         storage_dir/0
        ]).
-export([get_master/0,
         get_master_ip/0,
         get_master_port/0,
         get_admin/0,
         get_mode/0,
         get_crypto/0,
         is_test/0]).

-define(DEFAULT_IPV4_ADDRESS, {127,0,0,1}).
-define(DEFAULT_IPV6_ADDRESS, {0,0,0,0,0,0,0,1}).
-define(DEFAULT_PORT, 53).
-define(DEFAULT_NUM_WORKERS, 10).
-define(DEFAULT_ZONE_SERVER_PORT, 443).
-define(DEFAULT_WEBSOCKET_PATH, "/ws").

%% @doc Get the IP address (either IPv4 or IPv6) that the DNS server
%% should listen on.
%%
%% IPv4 default: 127.0.0.1
%% IPv6 default: ::1
%% Build a configuration for the server to enable multiple instances of servers to be started.
%% End config is something of [{{port, Port}, {listen, IPAddr}, {protocol, Proto}} | ....]
%% These configs are passed to the event handler and the server supervisors spawns children
%% using these built configs.
%% @end
-spec get_server_configs() -> {Pools :: term(), Servers :: term()}.
get_server_configs() ->
    ServerList = case application:get_env(erldns, servers) of
                     undefined ->
                         [];
                     {ok, ServerList0} ->
                         ServerList0
                 end,
    {Pools, Servers, _} =
        lists:foldl(fun(Server, {PoolAcc, ServerAcc, Inc}) ->
                            {port, Port} = lists:keyfind(port, 1, Server),
                            {listen, IPList0} = lists:keyfind(listen, 1, Server),
                            IPList = normalize_addresses(IPList0),
                            {protocol, Proto} = lists:keyfind(protocol, 1, Server),
                            {worker_pool, Pool} = lists:keyfind(worker_pool, 1, Server),
                            PoolName = list_to_atom("erldns_tcp_worker_pool_" ++ integer_to_list(Inc)),
                            NewPools = [lists:append([{name, PoolName}], Pool) | PoolAcc],
                            {NewPools, parse_server(IPList, Proto, Port, PoolName, ServerAcc), Inc + 1}
                    end, {[], [], 0}, ServerList),
    {Pools, Servers}.

%% @doc This function folds over a list of ip addresses (inet/inet6), if a address with all 0's
%% is encountered, all addresses of that type are removed from the result list.
%% @end
-spec normalize_addresses([{inet:address_family(), inet:ip_address()}]) -> [inet:ip_address()].
normalize_addresses(IPList) ->
    normalize_addresses(IPList, [] , [], [], []).

normalize_addresses([], Globalv4, Globalv6, Localv4, Localv6) ->
    Globalv4 ++ Globalv6 ++ Localv4 ++ Localv6;
normalize_addresses([IP | Tail], Globalv4, Globalv6, Localv4, Localv6) ->
    case parse_address(IP) of
        {inet, {0, 0, 0, 0}} = Addr ->
            normalize_addresses(Tail, [Addr], Globalv6, [], Localv6);
        {inet6, {0, 0, 0, 0, 0, 0, 0, 0}} = Addr->
            normalize_addresses(Tail, Globalv4, [Addr], Localv4, []);
        {inet, _} =  Addr when Globalv4 =:= []->
            normalize_addresses(Tail, Globalv4, Globalv6, [Addr | Localv4], Localv6);
        {inet, _} ->
            normalize_addresses(Tail, Globalv4, Globalv6, [], Localv6);
        {inet6, _} = Addr when Globalv6 =:= [] ->
            normalize_addresses(Tail, Globalv4, Globalv6, Localv4, [Addr | Localv6]);
        {inet6, _} ->
            normalize_addresses(Tail, Globalv4, Globalv6, Localv4, [])
    end.

%% @doc This function takes several parameters and creates the config for the server.
-spec parse_server([{inet:address_family(), inet:ip_address()}],[inet:socket_protocol()],
                   inet:port_number(), atom(), term()) -> term().
parse_server([], _ProtocolList, _Port, _PoolName, Acc) ->
    Acc;
parse_server([{IPType, IPAddr} = _IP | Tail], ProtocolList, Port, PoolName, Acc0) ->
    Acc = add_protocols(ProtocolList, IPType, IPAddr, Port, PoolName, Acc0),
    parse_server(Tail, ProtocolList, Port, PoolName, Acc).

add_protocols([], _IPType, _IPAddr, _Port, _PoolName, Acc) ->
    Acc;
add_protocols([Proto | Tail], IPType, IPAddr, Port, PoolName, Acc0) ->
    add_protocols(Tail, IPType, IPAddr, Port, PoolName,
                  [{IPType, IPAddr, Proto, Port, PoolName} | Acc0]).

get_address(inet) ->
    case application:get_env(erldns, inet4) of
        {ok, Address} -> parse(Address);
        _ -> [?DEFAULT_IPV4_ADDRESS]
    end;
get_address(inet6) ->
    case application:get_env(erldns, inet6) of
        {ok, Address} -> parse(Address);
        _ -> [?DEFAULT_IPV6_ADDRESS]
    end.

%% @doc The the port that the DNS server should listen on.
%%
%% Default: 53
-spec get_port() -> inet:port_number().
get_port() ->
    case application:get_env(erldns, port) of
        {ok, Port} -> Port;
        _ -> ?DEFAULT_PORT
    end.

%% @doc Get the number of workers to run for handling DNS requests.
%%
%% Default: 10
-spec get_num_workers() -> non_neg_integer().
get_num_workers() ->
    case application:get_env(erldns, num_workers) of
        {ok, NumWorkers} -> NumWorkers;
        _ -> ?DEFAULT_NUM_WORKERS
    end.

-spec use_root_hints() -> boolean().
use_root_hints() ->
    case application:get_env(erldns, use_root_hints) of
        {ok, Flag} -> Flag;
        _ -> true
    end.

%% Private functions
parse(IPList) ->
    parse(IPList, []).

parse([], Acc) ->
    Acc;
parse([{_,_,_,_} = IP | Tail], Acc) ->
    parse(Tail, [IP | Acc]);
parse([{_,_,_,_,_,_,_,_} = IP | Tail], Acc) ->
    parse(Tail, [IP | Acc]);
parse([IP | Tail], Acc) when is_binary(IP) ->
    parse(Tail, [parse_address(IP) | Acc]);
parse([IP | Tail], Acc) when is_list(IP) andalso length(IP) > 1 ->
    parse(Tail, [parse_address(IP) | Acc]);
parse(IP, Acc) when is_list(IP) ->
    [parse_address(IP) | Acc].

parse_address(Address) when is_binary(Address) ->
    parse_address(binary_to_list(Address));
parse_address(Address) when is_list(Address) ->
    {ok, Tuple} = inet_parse:address(Address),
    parse_address(Tuple);
parse_address({_,_,_,_,_,_,_,_} = Address) ->
    {inet6, Address};
parse_address({_,_,_,_} = Address) ->
    {inet, Address}.

zone_server_env() ->
    {ok, ZoneServerEnv} = application:get_env(erldns, zone_server),
    ZoneServerEnv.

zone_server_max_processes() ->
    proplists:get_value(max_processes, zone_server_env(), 16).

zone_server_protocol() ->
    proplists:get_value(protocol, zone_server_env(), "https").

zone_server_host() ->
    proplists:get_value(host, zone_server_env(), "localhost").

zone_server_port() ->
    proplists:get_value(port, zone_server_env(), ?DEFAULT_ZONE_SERVER_PORT).

websocket_env() ->
    proplists:get_value(websocket, zone_server_env(), []).

websocket_protocol() ->
    proplists:get_value(protocol, websocket_env(), wss).

websocket_host() ->
    proplists:get_value(host, websocket_env(), zone_server_host()).

websocket_port() ->
    proplists:get_value(port, websocket_env(), zone_server_port()).

websocket_path() ->
    proplists:get_value(path, websocket_env(), ?DEFAULT_WEBSOCKET_PATH).

websocket_url() ->
    atom_to_list(websocket_protocol()) ++ "://" ++ websocket_host() ++ ":" ++ integer_to_list(websocket_port()) ++ websocket_path().

storage_type() ->
    storage_get(type).

storage_dir() ->
    storage_get(dir).

storage_user() ->
    storage_get(user).

storage_pass() ->
    storage_get(pass).

storage_host() ->
    storage_get(host).

storage_port() ->
    storage_get(port).

storage_env() ->
    get_env(storage).

storage_get(Key) ->
    case lists:keyfind(Key, 1, get_env(storage)) of
        false ->
            undefined;
        {Key, Value} ->
            Value
    end.

get_env(storage) ->
    case application:get_env(erldns, storage) of
        undefined ->
            [{type, erldns_storage_json},
             {dir, undefined},
             {user, undefined},
             {pass, undefined},
             {host, undefined},
             {port, undefined}];
        {ok, Env} ->
            Env
    end.

get_master() ->
    case application:get_env(erldns, master_admin_server) of
        undefined ->
            undefined;
        {ok, {Addr, Port}} ->
            {Addr, Port}
    end.

get_master_ip() ->
    case application:get_env(erldns, master_admin_server) of
        undefined ->
            undefined;
        {ok, {Addr, _Port}} ->
            Addr
    end.

get_master_port() ->
    case application:get_env(erldns, master_admin_server) of
        undefined ->
            undefined;
        {ok, {_Addr, Port}} ->
            Port
    end.

get_admin() ->
    case application:get_env(erldns, admin) of
        undefined ->
            [];
        {ok, Admin} ->
            {keyget(listen, Admin), keyget(port, Admin)}
    end.

get_crypto() ->
    case application:get_env(erldns, crypto) of
        undefined ->
            undefined;
        {ok, Crypto} ->
            {keyget(key, Crypto), keyget(vector, Crypto)}
    end.

get_mode() ->
    case application:get_env(erldns, mode) of
        undefined ->
            public;
        {ok, public} ->
            public;
        {ok, hidden} ->
            hidden
    end.

is_test() ->
    case application:get_env(erldns, test) of
        {ok, true} ->
            true;
        {ok, false} ->
            false;
        undefined ->
            false
    end.

keyget(Key, Data) ->
    {Key, Value} = lists:keyfind(Key, 1, Data),
    Value.
