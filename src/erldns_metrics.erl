-module(erldns_metrics).

-behavior(gen_server).

% Public API
-export([start_link/0, measure/4]).

% Gen server hooks
-export([init/1,
	 handle_call/3,
	 handle_cast/2,
	 handle_info/2,
	 terminate/2,
	 code_change/3
       ]).

-define(SERVER, ?MODULE).

-record(state, {stathat_ezid}).

% Public API
start_link() ->
  gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

measure(_Name, Module, FunctionName, Args) when is_list(Args) ->
  {T, R} = timer:tc(Module, FunctionName, Args),
  gen_server:cast(?SERVER, {record_timing, Module, FunctionName, T/1000}),
  %lager:debug([{tag, timer_result}], "~p:~p (~p) took ~p ms", [Module, FunctionName, Name, T / 1000]),
  R;
measure(Name, Module, FunctionName, Arg) -> measure(Name, Module, FunctionName, [Arg]).

% Gen server functions
init(_) ->
  case application:get_env(erldns, stathat_email) of
    {ok, EzId} -> {ok, #state{stathat_ezid = EzId}};
    _ -> {ok, #state{stathat_ezid = inactive}}
  end.

handle_call(_Message, _From, State) ->
  {reply, ok, State}.

handle_cast({record_timing, Module, FunctionName, Value}, State) ->
  case State#state.stathat_ezid of
    inactive -> ok;
    EzId -> stathat:ez_value(EzId, lists:flatten(io_lib:format("~p ~p", [Module, FunctionName])), Value)
  end,
  {noreply, State}.

handle_info(_Message, State) ->
  {noreply, State}.

terminate(_Reason, _State) ->
  ok.

code_change(_PreviousVersion, State, _Extra) ->
  {ok, State}.
