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

%% @doc Application event handler implementation.
-module(erldns_event_handler).

-behavior(gen_event).

-export([
         init/1,
         handle_event/2,
         handle_call/2,
         handle_info/2,
         code_change/3,
         terminate/2
        ]).

-record(state, {servers_running = false}).

init(_Args) ->
  {ok, #state{}}.

handle_event(start_servers, State) ->
  case State#state.servers_running of
    false ->
      % Start up the UDP and TCP servers
      erldns_log:info("Starting the UDP and TCP supervisor"),
        {ok, _Pid} = erldns_server_sup:start_link(),
        {Pools, Configs} = erldns_config:get_server_configs(),
        erldns_log:info("Pools: ~p, Configs; ~p", [Pools, Configs]),
        add_pools(Pools),
        add_servers(lists:flatten([erldns_config:get_admin() | Configs])),
      erldns_events:notify(servers_started),
      {ok, State#state{servers_running = true}};
    _ ->
      erldns_events:notify(servers_already_started),
      {ok, State}
  end;

handle_event({end_udp, [{host, _Host}]}, State) ->
  folsom_metrics:notify({udp_request_meter, 1}),
  folsom_metrics:notify({udp_request_counter, {inc, 1}}),
  {ok, State};

handle_event({end_tcp, [{host, _Host}]}, State) ->
  folsom_metrics:notify({tcp_request_meter, 1}),
  folsom_metrics:notify({tcp_request_counter, {inc, 1}}),
  {ok, State};

handle_event(_Event, State) ->
  {ok, State}.

handle_call(_Message, State) ->
  {ok, ok, State}.

handle_info(_Message, State) ->
  {ok, State}.

code_change(_OldVsn, State, _Extra) ->
  {ok, State}.

terminate(_Reason, _State) ->
  ok.

add_servers([]) ->
    ok;
add_servers([{inet, {_, _, _, _} = IPAddr, tcp, Port, PoolName}| Tail]) ->
    Spec = {{tcp_inet, IPAddr}, {erldns_tcp_server, start_link, [tcp_inet, inet, IPAddr, Port, PoolName]},
        permanent, 5000, worker, [erldns_tcp_server]},
    erldns_log:info("Starting server child with spec: ~p", [Spec]),
    ok = start_child(Spec),
    add_servers(Tail);
add_servers([{inet6, {_, _, _, _, _, _, _, _} = IPAddr, tcp, Port, PoolName}| Tail]) ->
    Spec = {{tcp_inet6, IPAddr}, {erldns_tcp_server, start_link, [tcp_inet6, inet6, IPAddr, Port, PoolName]},
        permanent, 5000, worker, [erldns_tcp_server]},
    erldns_log:info("Starting server child with spec: ~p", [Spec]),
    ok = start_child(Spec),
    add_servers(Tail);
add_servers([{inet, {_, _, _, _} = IPAddr, udp, Port, _}| Tail]) ->
    Spec = {{udp_inet, IPAddr}, {erldns_udp_server, start_link, [udp_inet, inet, IPAddr, Port]},
        permanent, 5000, worker, [erldns_udp_server]},
    erldns_log:info("Starting server child with spec: ~p", [Spec]),
    ok = start_child(Spec),
    add_servers(Tail);
add_servers([{inet6, {_, _, _, _, _, _, _, _} = IPAddr, udp, Port, _}| Tail]) ->
    Spec = {{udp_inet6, IPAddr}, {erldns_udp_server, start_link, [udp_inet6, inet6, IPAddr, Port]},
    permanent, 5000, worker, [erldns_udp_server]},
    erldns_log:info("Starting server child with spec: ~p", [Spec]),
    ok = start_child(Spec),
    add_servers(Tail);
add_servers([{Addr, Port} | Tail]) ->
    Spec =  {erldns_admin_server, {erldns_admin_server, start_link, [erldns_admin_server, Addr, Port]},
        permanent, 5000, worker, [erldns_admin_server]},
    ok = start_child(Spec),
    add_servers(Tail).

add_pools([]) ->
    ok;
add_pools([Pool | Tail]) ->
    Name = keyget(name, Pool),
    Args = [{name, {local, Name}},
            {worker_module, erldns_worker},
            {size, keyget(size, Pool)},
            {max_overflow, keyget(max_overflow, Pool)}],
    Spec = poolboy:child_spec(Name, Args),
    ok = start_child(Spec),
    add_pools(Tail).

keyget(Key, Data) ->
    {Key, Value} = lists:keyfind(Key, 1, Data),
    Value.

%% @doc We only want to crash if its already started. If its present, that's fine.
-spec start_child(term()) -> ok | {error, any()}.
start_child(Spec) ->
    case supervisor:start_child(erldns_server_sup, Spec) of
        {ok, _Pid} ->
            ok;
        {error, {already_started, Pid}} ->
            {error, {already_started, Pid}};
        {error, already_present} ->
            ok
    end.

