-module(erldns_metrics).

-behavior(gen_server).

-export([start_link/0]).

-define(DEFAULT_PORT, 8082).

% Gen server hooks
-export([init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3
  ]).

-record(state, {}).

start_link() ->
  gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

init([]) ->
  lager:debug("Starting ~p", [?MODULE]),

  Dispatch = cowboy_router:compile(
    [
      {'_', 
        [
          {"/", erldns_metrics_root_handler, []}
        ]
      }
    ]
  ),

  {ok, _} = cowboy:start_http(http, 10, [{port, port()}], [{env, [{dispatch, Dispatch}]}]),

  {ok, #state{}}.

handle_call(_Message, _From, State) ->
  {reply, ok, State}.
handle_cast(_, State) ->
  {noreply, State}.
handle_info(_, State) ->
  {noreply, State}.
terminate(_, _) ->
  ok.
code_change(_PreviousVersion, State, _Extra) ->
  {ok, State}.

port() ->
 proplists:get_value(port, metrics_env(), ?DEFAULT_PORT).

metrics_env() ->
  case application:get_env(erldns, metrics) of
    {ok, MetricsEnv} -> MetricsEnv;
    _ -> []
  end.
