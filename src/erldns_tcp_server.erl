%% Copyright (c) 2012-2018, DNSimple Corporation
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

% API
-export([start_link/2, start_link/4]).

% Gen server hooks
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         sock_opts/0,
         new_connection/2,
         code_change/3
        ]).

% Internal API
-export([handle_request/3]).

-define(SERVER, ?MODULE).

-record(state, {port, workers}).

%% Public API
-spec start_link(atom(), inet | inet6) -> {ok, pid()} | ignore | {error, term()}.
start_link(Name, Family) ->
  start_link(Name, Family, erldns_config:get_address(Family), erldns_config:get_port()).

-spec start_link(atom(), inet | inet6, inet:ip_address(), inet:port_number()) -> {ok, pid()} | ignore | {error, term()}.
start_link(_Name, Family, Address, Port) ->
  lager:info("Starting TCP server for ~p on address ~p port ~p", [Family, Address, Port]),
  gen_nb_server:start_link(?MODULE, Address, Port, []).

%% gen_server hooks
init([]) ->
  {ok, #state{workers = make_workers(queue:new())}}.
handle_call(_Request, _From, State) ->
  {reply, ok, State}.
handle_cast(_Message, State) ->
  {noreply, State}.
handle_info({tcp, Socket, Bin}, State) ->
  Response = folsom_metrics:histogram_timed_update(tcp_handoff_histogram, ?MODULE, handle_request, [Socket, Bin, State]),
  Response;
handle_info(_Message, State) ->
  {noreply, State}.
terminate(_Reason, _State) ->
  ok.
sock_opts() ->
  [binary, {reuseaddr, true}].
new_connection(Socket, State) ->
  inet:setopts(Socket, [{active, once}]),
  {ok, State}.
code_change(_PreviousVersion, State, _Extra) ->
  {ok, State}.

handle_request(Socket, Bin, State) ->
  case queue:out(State#state.workers) of
    {{value, Worker}, Queue} ->
      gen_server:cast(Worker, {tcp_query, Socket, Bin}),
      {noreply, State#state{workers = queue:in(Worker, Queue)}};
    {empty, _Queue} ->
      folsom_metrics:notify({packet_dropped_empty_queue_counter, {inc, 1}}),
      folsom_metrics:notify({packet_dropped_empty_queue_meter, 1}),
      lager:info("Queue is empty, dropping packet"),
      {noreply, State}
  end.

make_workers(Queue) ->
  make_workers(Queue, erldns_config:get_num_workers()).
make_workers(Queue, NumWorkers) ->
  make_workers(Queue, NumWorkers, 1).
make_workers(Queue, NumWorkers, N) ->
  case N < NumWorkers of
    true ->
      {ok, WorkerPid} = erldns_worker:start_link([{tcp, N}]),
      make_workers(queue:in(WorkerPid, Queue), NumWorkers, N + 1);
    false ->
      Queue
  end.
