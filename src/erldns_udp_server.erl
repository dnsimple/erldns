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

%% @doc Handles DNS questions arriving via UDP.
-module(erldns_udp_server).
-behavior(gen_server).

%% API
-export([start_link/4, is_running/0]).

%% Gen server hooks
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3
        ]).

%% Internal API
-export([handle_request/5]).

-define(SERVER, ?MODULE).

-record(state, {port, listen_ip, socket, workers}).

%% Public API

%% @doc Start the UDP server process
-spec start_link(atom(), inet | inet6, inet:ip_address(), non_neg_integer()) -> {ok, pid()} | ignore
                                                                                    | {error, term()}.
start_link(_Name, InetFamily, ListenIP, Port) ->
    gen_server:start_link(?MODULE, [InetFamily, ListenIP, Port], []).

%% @doc Return true if the UDP server process is running
-spec is_running() -> boolean().
is_running() ->
    try sys:get_state(udp_inet) of
        _ -> true
    catch
        _ -> false
    end.


%% gen_server hooks
init([InetFamily, ListenIP, Port]) ->
    {ok, Socket} = start(Port, InetFamily, ListenIP),
    {ok, #state{port = Port, listen_ip = ListenIP, socket = Socket, workers = make_workers(queue:new())}}.
handle_call(_Request, _From, State) ->
    {reply, ok, State}.
handle_cast(_Message, State) ->
    {noreply, State}.
handle_info(timeout, State) ->
                                                %erldns_log:info("UDP instance timed out"),
    {noreply, State};
handle_info({udp, Socket, ClientIP, Port, Bin}, State) ->
    Response = folsom_metrics:histogram_timed_update(udp_handoff_histogram, ?MODULE, handle_request,
                                                     [Socket, ClientIP, Port, Bin, State]),
    inet:setopts(State#state.socket, [{active, once}]),
    Response;
handle_info(_Message, State) ->
    {noreply, State}.
terminate(_Reason, _State) ->
    ok.
code_change(_PreviousVersion, State, _Extra) ->
    {ok, State}.

%% Internal functions
%% Start a UDP server.
start(Port, InetFamily, ListenIP) ->
    erldns_log:info("Starting UDP server for ~p on port ~p", [InetFamily, Port]),
    case gen_udp:open(Port, [binary, {active, once}, {read_packets, 1000}, {ip, ListenIP}, InetFamily]) of
        {ok, Socket} ->
            erldns_log:info("UDP server (~p) on IP ~p opened socket: ~p", [InetFamily, ListenIP, Socket]),
            {ok, Socket};
        {error, eacces} ->
            erldns_log:error("Failed to open UDP socket. Need to run as sudo?"),
            {error, eacces}
    end.

%% This function executes in a single process and thus
%% must return very fast. The execution time of this function
%% will determine the overall QPS of the system.
handle_request(Socket, ClientIP, Port, Bin, State) ->
    case queue:out(State#state.workers) of
        {{value, Worker}, Queue} ->
            gen_server:cast(Worker, {udp_query, Socket, ClientIP, Port, Bin}),
            {noreply, State#state{workers = queue:in(Worker, Queue)}};
        {empty, _Queue} ->
            folsom_metrics:notify({packet_dropped_empty_queue_counter, {inc, 1}}),
            folsom_metrics:notify({packet_dropped_empty_queue_meter, 1}),
            erldns_log:info("Queue is empty, dropping packet"),
            {noreply, State}
    end.

make_workers(Queue) ->
    make_workers(Queue, erldns_config:get_num_workers()).
make_workers(Queue, NumWorkers) ->
    make_workers(Queue, NumWorkers, 1).
make_workers(Queue, NumWorkers, N) ->
    case N < NumWorkers of
        true ->
            {ok, WorkerPid} = erldns_worker:start_link([]),
            make_workers(queue:in(WorkerPid, Queue), NumWorkers, N + 1);
        false ->
            Queue
    end.
