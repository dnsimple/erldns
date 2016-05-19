-module(erldns_metrics).

-behaviour(gen_server).

%% API functions
-export([
         start_link/0,
         update/2,
         timed_update/2,
         timed_update/3,
         timed_update/4
        ]).

%% gen_server callbacks
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

-record(state, {
          module :: module()
         }).

%%%===================================================================
%%% API functions
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%%
%% @spec start_link() -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
start_link() ->
    App = application:get_env(erldns, metrics, exometer),
    gen_server:start_link({local, ?MODULE}, ?MODULE, [App], []).

update(Metrics, Value) ->
    gen_server:cast(?MODULE, {update, Metrics, Value}).

timed_update(Metrics, Fun) ->
    gen_server:call(?MODULE, {tc, Metrics, Fun, []}, infinity).

timed_update(Metrics, Fun, Args) ->
    gen_server:call(?MODULE, {tc, Metrics, Fun, Args}, infinity).

timed_update(Metrics, M, F, A) ->
    gen_server:call(?MODULE, {tc, Metrics, M, F, A}).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Initializes the server
%%
%% @spec init(Args) -> {ok, State} |
%%                     {ok, State, Timeout} |
%%                     ignore |
%%                     {stop, Reason}
%% @end
%%--------------------------------------------------------------------
init([folsom]) ->
    application:ensure_all_started(folsom),
    folsom_metrics:new_counter(udp_request_counter),
    folsom_metrics:new_counter(tcp_request_counter),
    folsom_metrics:new_meter(udp_request_meter),
    folsom_metrics:new_meter(tcp_request_meter),

    folsom_metrics:new_meter(udp_error_meter),
    folsom_metrics:new_meter(tcp_error_meter),
    folsom_metrics:new_history(udp_error_history),
    folsom_metrics:new_history(tcp_error_history),

    folsom_metrics:new_meter(refused_response_meter),
    folsom_metrics:new_counter(refused_response_counter),

    folsom_metrics:new_meter(empty_response_meter),
    folsom_metrics:new_counter(empty_response_counter),

    folsom_metrics:new_histogram(udp_handoff_histogram),
    folsom_metrics:new_histogram(tcp_handoff_histogram),

    folsom_metrics:new_counter(request_throttled_counter),
    folsom_metrics:new_meter(request_throttled_meter),
    folsom_metrics:new_histogram(request_handled_histogram),

    folsom_metrics:new_counter(packet_dropped_empty_queue_counter),
    folsom_metrics:new_meter(packet_dropped_empty_queue_meter),

    folsom_metrics:new_meter(cache_hit_meter),
    folsom_metrics:new_meter(cache_expired_meter),
    folsom_metrics:new_meter(cache_miss_meter),

    folsom_metrics:new_counter(dnssec_request_counter),
    folsom_metrics:new_meter(dnssec_request_meter),
    {ok, #state{module=folsom_metrics}};

init([exometer]) ->
    application:ensure_all_started(exometer_core),
    exometer:new([erldns, udp_request_counter], counter),
    exometer:new([erldns, tcp_request_counter], counter),
    exometer:new([erldns, udp_request_meter], spiral),
    exometer:new([erldns, tcp_request_meter], spiral),

    exometer:new([erldns, udp_error_meter], spiral),
    exometer:new([erldns, tcp_error_meter], spiral),
    exometer:new([erldns, udp_error_history], history),
    exometer:new([erldns, tcp_error_history], history),

    exometer:new([erldns, refused_response_meter], spiral),
    exometer:new([erldns, refused_response_counter], counter),

    exometer:new([erldns, empty_response_meter], spiral),
    exometer:new([erldns, empty_response_counter], spiral),

    exometer:new([erldns, udp_handoff_histogram], histogram),
    exometer:new([erldns, tcp_handoff_histogram], histogram),

    exometer:new([erldns, request_throttled_counter], counter),
    exometer:new([erldns, request_throttled_meter], spiral),
    exometer:new([erldns, request_handled_histogram], histogram),

    exometer:new([erldns, packet_dropped_empty_queue_counter], counter),
    exometer:new([erldns, packet_dropped_empty_queue_meter], spiral),

    exometer:new([erldns, cache_hit_meter], spiral),
    exometer:new([erldns, cache_expired_meter], spiral),
    exometer:new([erldns, cache_miss_meter], spiral),

    exometer:new([erldns, dnssec_request_counter], counter),
    exometer:new([erldns, dnssec_request_meter], spiral),
    {ok, #state{module=exometer}}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling call messages
%%
%% @spec handle_call(Request, From, State) ->
%%                                   {reply, Reply, State} |
%%                                   {reply, Reply, State, Timeout} |
%%                                   {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, Reply, State} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_call({tc, Metric, M, F, A}=Args, _From, #state{module=folsom_metrics} = State) ->
    lager:debug("Folsom tc: ~p", [Args]),
    Reply = folsom_metrics:histogram_timed_update(Metric, M, F, A),
    lager:debug("Folsom tc out: ~p", [Reply]),
    {reply, Reply, State};
handle_call({tc, Metric, Fun, Args}, _From, #state{module=folsom_metrics} = State) ->
    Reply = folsom_metrics:histogram_timed_update(Metric, Fun, Args),
    {reply, Reply, State};
handle_call({tc, Metric, M, F, A}, _From, #state{module=exometer} = State) ->
    {Time, Value} = timer:tc(M, F, A),
    exometer:update([erldns, Metric], Time),
    {reply, Value, State};
handle_call({tc, Metric, Fun, Args}, _From, #state{module=exometer} = State) ->
    {Time, Value} = timer:tc(Fun, Args),
    exometer:update([erldns, Metric], Time),
    {reply, Value, State};
handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling cast messages
%%
%% @spec handle_cast(Msg, State) -> {noreply, State} |
%%                                  {noreply, State, Timeout} |
%%                                  {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_cast({update, Metric, Value}, #state{module=folsom_metrics} = State) ->
    MetricInfo0 = folsom_metrics:get_metric_info(Metric),
    MetricInfo = proplists:get_value(Metric, MetricInfo0),
    case proplists:get_value(type, MetricInfo) of
        counter -> folsom_metrics:notify({Metric, {inc, Value}});
        _ -> folsom_metrics:notify({Metric, Value})
    end,
    {reply, State};
handle_cast({update, Metric, Value}, #state{module=exometer} = State) ->
    exometer:update([erldns, Metric], Value),
    {noreply, State};
handle_cast(_Msg, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling all non call/cast messages
%%
%% @spec handle_info(Info, State) -> {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_info(_Info, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_server terminates
%% with Reason. The return value is ignored.
%%
%% @spec terminate(Reason, State) -> void()
%% @end
%%--------------------------------------------------------------------
terminate(_Reason, _State) ->
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%%
%% @spec code_change(OldVsn, State, Extra) -> {ok, NewState}
%% @end
%%--------------------------------------------------------------------
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
