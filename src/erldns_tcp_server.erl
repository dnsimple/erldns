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

%% @doc Handles DNS questions arriving via TCP.
-module(erldns_tcp_server).
-behavior(gen_nb_server).

%% API
-export([start_link/5]).

%% Gen server hooks
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         sock_opts/0,
         new_connection/2,
         code_change/3
        ]).

%% Internal API
-export([handle_request/3]).

-define(SERVER, ?MODULE).

-record(state, {port, listen_ip, pool_name}).

%% Public API
start_link(_Name, Family, ListenIP, Port, PoolName) ->
    erldns_log:info("Starting TCP server for ~p on port ~p, IP ~p", [Family, Port, ListenIP]),
    gen_nb_server:start_link(?MODULE, ListenIP, Port, [Port, ListenIP, PoolName]).

%% gen_server hooks
init([Port, ListenIP, PoolName]) ->
    {ok, #state{port = Port, listen_ip = ListenIP, pool_name = PoolName}}.

handle_call(get_addr, _From, State) ->
    {reply, State#state.listen_ip, State};
handle_call(_Request, _From, State) ->
    {ok, State}.

handle_cast(_Message, State) ->
    {noreply, State}.

handle_info({tcp, Socket, Bin}, #state{listen_ip = _ListenIP, pool_name = PoolName} = State) ->
    folsom_metrics:histogram_timed_update(tcp_handoff_histogram, ?MODULE, handle_request,
                                          [PoolName, Socket, Bin]),
    {noreply, State};
handle_info(_Message, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

sock_opts() ->
    [binary].

new_connection(Socket, State) ->
    inet:setopts(Socket, [{active, once}]),
    {ok, State}.

code_change(_PreviousVersion, State, _Extra) ->
    {ok, State}.

handle_request(PoolName, Socket, Bin) ->
    poolboy:transaction(PoolName, fun(Worker) ->
                                          gen_server:call(Worker, {tcp_query, Socket, Bin})
                                  end).
