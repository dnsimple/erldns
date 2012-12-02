-module(erldns_metrics).

-behavior(gen_server).

% Public API
-export([start_link/0, insert/2, display/0, slowest/0]).

% Gen server hooks
-export([init/1,
	 handle_call/3,
	 handle_cast/2,
	 handle_info/2,
	 terminate/2,
	 code_change/3
       ]).

-define(SERVER, ?MODULE).

-record(state, {data=[]}).

% Public API
start_link() ->
  gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

insert(Name, Time) ->
  gen_server:cast(?SERVER, {insert, Name, Time}).

display() ->
  gen_server:cast(?SERVER, {display}).

slowest() ->
  gen_server:cast(?SERVER, {display, slowest}).

% Gen server functions
init(_) ->
  {ok, #state{}}.

handle_call({insert, Name, Time}, _From, State) -> 
  {reply, ok, State#state{data = State#state.data ++ [{Name, Time}]}}.

handle_cast({insert, Name, Time}, State) ->
  {noreply, State#state{data = State#state.data ++ [{Name, Time}]}};
handle_cast({display}, State) ->
  display_list(State#state.data),
  {noreply, State};
handle_cast({display, slowest}, State) ->
  Sorted = lists:sort(fun({_, A}, {_, B}) -> A > B end, State#state.data),
  display_list(Sorted),
  {noreply, State}.

handle_info(_Message, State) ->
  {noreply, State}.

terminate(_Reason, _State) ->
  ok.

code_change(_PreviousVersion, State, _Extra) ->
  {ok, State}.

% Internal API

display_list({Name, T}) -> lager:info("~p: ~p ms", [Name, T / 1000]).
