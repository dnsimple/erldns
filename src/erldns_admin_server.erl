%% Copyright (c) 2014, SiftLogic LLC
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

%% @doc Handles admin server. A started slave will wuery this server in order to get the zones
%% it should have. Then it shall initiate an AXFR request to the master.
%% @end

-module(erldns_admin_server).
-behavior(gen_nb_server).

%% API
-export([start_link/3]).

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

-define(SERVER, ?MODULE).

-record(state, {port, listen_ip}).

%% Public API
start_link(_Name, ListenIP, Port) ->
    erldns_log:info("Starting ADMIN server on port ~p, IP ~p", [Port, ListenIP]),
    gen_nb_server:start_link(?MODULE, ListenIP, Port, [Port, ListenIP]).

%% gen_server hooks
init([Port, ListenIP]) ->
    {ok, #state{port = Port, listen_ip = ListenIP}}.

handle_call(_Request, _From, State) ->
    {ok, State}.

handle_cast(_Message, State) ->
    {noreply, State}.

handle_info({tcp, Socket, <<"slave_startup_",  IP/binary>>}, State) ->
    erldns_log:info("Got some info up in here! IP ~p", [binary_to_term(IP)]),
    gen_tcp:send(Socket,
                 term_to_binary(erldns_zone_cache:get_zone_names_for_slave(binary_to_term(IP)))),
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
