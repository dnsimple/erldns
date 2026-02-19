-module(erldns_proto_tcp).
-moduledoc false.

-include_lib("kernel/include/logger.hrl").
-include_lib("dns_erlang/include/dns.hrl").

-define(LOG_METADATA, #{domain => [erldns, listeners]}).

-define(SOCKET_ERROR(State),
    ((Error =:= tcp_error andalso State#state.socket_type =:= tcp) orelse
        (Error =:= ssl_error andalso State#state.socket_type =:= ssl))
).

-define(SOCKET_CLOSED(State),
    ((Closed =:= tcp_closed andalso State#state.socket_type =:= tcp) orelse
        (Closed =:= ssl_closed andalso State#state.socket_type =:= ssl))
).

-behaviour(ranch_protocol).
-export([start_link/3]).

-behaviour(gen_server).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-type socket() :: inet:socket() | ssl:sslsocket().
-type socket_type() :: tcp | ssl.
-type ts() :: integer().
-export_type([socket/0, socket_type/0, ts/0]).

-record(request, {
    start_time :: ts(),
    request_bin :: dns:message_bin(),
    timeout_timer :: reference()
}).
-type request() :: #request{}.

-record(state, {
    socket :: socket(),
    socket_type :: socket_type(),
    connection_start_time :: ts(),
    ingress_timeout_ms :: non_neg_integer(),
    idle_timeout_ms :: non_neg_integer(),
    request_timeout_ms :: non_neg_integer(),
    max_concurrent_queries :: non_neg_integer(),
    ip_address :: inet:ip_address(),
    port :: inet:port_number(),
    active_workers = #{} :: #{pid() => request()},
    timer_ref :: undefined | reference(),
    buffer = <<>> :: binary()
}).
-type state() :: #state{}.

-spec start_link(ranch:ref(), module(), #{atom() => term()}) -> {ok, pid()}.
start_link(Ref, Transport, Opts) ->
    SpawnOpts = [link],
    Params = [{Ref, Transport, Opts, erlang:monotonic_time()}],
    Pid = proc_lib:spawn_opt(?MODULE, init, Params, SpawnOpts),
    {ok, Pid}.

-spec init({ranch:ref(), module(), #{atom() => term()}, ts()}) -> {ok, state()} | {stop, term()}.
init({Ref, Transport, Opts, StartTime}) ->
    process_flag(trap_exit, true),
    MaybeState =
        try
            SocketType = detect_socket_type(Transport),
            #{
                max_concurrent_queries := MaxConcurrentQueries,
                ingress_request_timeout := IngressTimeoutMs,
                idle_timeout_ms := IdleTimeoutMs,
                request_timeout_ms := RequestTimeoutMs
            } = Opts,
            {ok, Socket} = ranch:handshake(Ref),
            {ok, {IpAddr, Port}} = get_peername(Socket, SocketType),
            ok = set_socket_active(Socket, SocketType),
            #state{
                socket = Socket,
                socket_type = SocketType,
                connection_start_time = StartTime,
                ingress_timeout_ms = IngressTimeoutMs,
                idle_timeout_ms = IdleTimeoutMs,
                request_timeout_ms = RequestTimeoutMs,
                max_concurrent_queries = MaxConcurrentQueries,
                ip_address = IpAddr,
                port = Port,
                timer_ref = erlang:start_timer(IngressTimeoutMs, self(), ingress)
            }
        catch
            Class:Reason:Stacktrace ->
                ExceptionMetadata = #{
                    what => connection_init_failed,
                    transport => tcp,
                    kind => Class,
                    reason => Reason,
                    stacktrace => Stacktrace
                },
                telemetry:execute([erldns, request, error], #{count => 1}, ExceptionMetadata),
                {stop, {init_failed, Class, Reason}}
        end,
    case MaybeState of
        #state{} -> gen_server:enter_loop(?MODULE, [], MaybeState);
        _ -> MaybeState
    end.

-spec handle_call(dynamic(), gen_server:from(), state()) -> {reply, dynamic(), state()}.
handle_call(_Request, _From, State) ->
    {reply, {error, not_implemented}, State}.

-spec handle_cast(dynamic(), state()) -> {noreply, state()}.
handle_cast(_Msg, State) ->
    {noreply, State}.

-spec handle_info(dynamic(), state()) -> {noreply, state()} | {stop, normal | term(), state()}.
handle_info({timeout, TimerRef, idle}, #state{timer_ref = TimerRef} = State) ->
    ?LOG_DEBUG(#{what => connection_idle_timeout, transport => tcp}, ?LOG_METADATA),
    {stop, normal, State};
handle_info({timeout, TimerRef, ingress}, #state{timer_ref = TimerRef} = State) ->
    ?LOG_INFO(#{what => connection_ingress_timeout, transport => tcp}, ?LOG_METADATA),
    Count = 1 + maps:size(State#state.active_workers),
    Metadata = #{transport => tcp, timeout_type => ingress, buffer => State#state.buffer},
    telemetry:execute([erldns, request, dropped], #{count => Count}, Metadata),
    {stop, normal, State};
handle_info({timeout, TimerRef, {request_timeout, WorkerPid}}, #state{} = State) ->
    handle_worker_timeout(WorkerPid, TimerRef, State);
handle_info({timeout, _, _}, #state{} = State) ->
    % Timer was cancelled/replaced, ignore
    {noreply, State};
handle_info({'EXIT', Pid, normal}, #state{} = State) ->
    handle_worker_down(Pid, State);
handle_info({'EXIT', Pid, killed}, #state{} = State) ->
    handle_worker_down(Pid, State);
handle_info({'EXIT', Pid, Reason}, #state{} = State) ->
    ?LOG_WARNING(#{what => tcp_worker_crashed, pid => Pid, reason => Reason}, ?LOG_METADATA),
    handle_worker_down(Pid, State);
handle_info({SocketType, Socket, Bin}, #state{socket = Socket, socket_type = SocketType} = State) ->
    % Placeholder for future Active Queue Management implementations
    NewBuffer = <<(State#state.buffer)/binary, Bin/binary>>,
    handle_process_buffer(State#state{buffer = NewBuffer});
handle_info({Error, Socket, Reason}, #state{socket = Socket} = State) when ?SOCKET_ERROR(State) ->
    ?LOG_NOTICE(#{what => socket_error, reason => Reason}, ?LOG_METADATA),
    {stop, normal, State};
handle_info({Closed, Socket}, #state{socket = Socket} = State) when ?SOCKET_CLOSED(State) ->
    {stop, normal, State};
handle_info(Info, State) ->
    ?LOG_INFO(#{what => unexpected_info, info => Info}, ?LOG_METADATA),
    {noreply, State}.

-spec terminate(term(), state()) -> ok.
terminate(_Reason, State) ->
    shutdown(State).

-spec handle_worker_down(pid(), state()) -> {noreply, state()}.
handle_worker_down(Pid, #state{active_workers = ActiveWorkers} = State) ->
    {RequestInfo, NewActiveWorkers} = maps:take(Pid, ActiveWorkers),
    cancel_timer(RequestInfo#request.timeout_timer),
    State1 = State#state{active_workers = NewActiveWorkers},
    handle_process_buffer(State1).

-define(CONCURRENT_QUERIES_EMPTY(S),
    0 =:= map_size(S#state.active_workers)
).
-define(CONCURRENT_QUERIES_FULL(S),
    S#state.max_concurrent_queries =:= map_size(S#state.active_workers)
).
-define(CONCURRENT_QUERIES_NOT_FULL(S),
    S#state.max_concurrent_queries =/= map_size(S#state.active_workers)
).

-spec handle_process_buffer(state()) -> {noreply, state()}.
%% If we have a full packet, we spawn only if there is available concurrency, otherwise we do
%% nothing, no timer nor socket reads, we just wait for a worker to finish and free a slot
handle_process_buffer(#state{buffer = <<Len:16, RequestBin:Len/binary, Rest/binary>>} = State) when
    ?CONCURRENT_QUERIES_NOT_FULL(State)
->
    spawn_tcp_worker_and_recurse(State, RequestBin, Rest);
handle_process_buffer(#state{buffer = <<Len:16, _:Len/binary, _/binary>>} = State) ->
    {noreply, State};
%% If we have a non-empty piece of a packet, we can assume the sender has sent all of it
%% and we'll try to read it in order to avoid more TCP replays than needed, until we hit either the
%% cases above (full packet and maybe spawn) and eventually the cases below, with no pending packet
handle_process_buffer(#state{buffer = <<_, _/binary>>} = State) ->
    set_socket_active(State#state.socket, State#state.socket_type),
    ensure_ingress_timer(State);
%% If the buffer is empty, it is because we've already triggered all pending requests:
%% - We'll become idle only if there's no pending active workers
%% - Or we'll set the socket active if the active workers is not full
handle_process_buffer(#state{buffer = <<>>} = State) when ?CONCURRENT_QUERIES_EMPTY(State) ->
    set_socket_active(State#state.socket, State#state.socket_type),
    start_idle_timer(State);
handle_process_buffer(#state{buffer = <<>>} = State) when ?CONCURRENT_QUERIES_NOT_FULL(State) ->
    set_socket_active(State#state.socket, State#state.socket_type),
    {noreply, State};
handle_process_buffer(#state{buffer = <<>>} = State) when ?CONCURRENT_QUERIES_FULL(State) ->
    {noreply, State}.

-spec spawn_tcp_worker_and_recurse(state(), dns:message_bin(), binary()) -> {noreply, state()}.
spawn_tcp_worker_and_recurse(
    #state{
        socket = Socket,
        socket_type = SocketType,
        ip_address = IpAddr,
        port = Port,
        active_workers = ActiveWorkers,
        request_timeout_ms = RequestTimeoutMs,
        timer_ref = TimerRef
    } = State,
    RequestBin,
    Rest
) ->
    TS = erlang:monotonic_time(),
    WorkerPid = erldns_proto_tcp_request:start_link(
        RequestBin, TS, Socket, SocketType, IpAddr, Port
    ),
    TimeoutTimer = erlang:start_timer(RequestTimeoutMs, self(), {request_timeout, WorkerPid}),
    cancel_timer(TimerRef),
    RequestInfo = #request{
        start_time = TS,
        request_bin = RequestBin,
        timeout_timer = TimeoutTimer
    },
    State1 = State#state{
        buffer = Rest,
        active_workers = ActiveWorkers#{WorkerPid => RequestInfo},
        timer_ref = undefined
    },
    handle_process_buffer(State1).

-spec start_idle_timer(state()) -> {noreply, state()}.
start_idle_timer(#state{idle_timeout_ms = IdleTimeoutMs, timer_ref = TimerRef} = State) ->
    cancel_timer(TimerRef),
    NewTimerRef = erlang:start_timer(IdleTimeoutMs, self(), idle),
    {noreply, State#state{timer_ref = NewTimerRef}}.

%% In order to avoid slow-read attacks, we enforce a timeout for receiving a whole packet
-spec ensure_ingress_timer(state()) -> {noreply, state()}.
ensure_ingress_timer(
    #state{ingress_timeout_ms = Timeout, timer_ref = undefined} = State
) ->
    TimerRef = erlang:start_timer(Timeout, self(), ingress),
    {noreply, State#state{timer_ref = TimerRef}};
ensure_ingress_timer(#state{} = State) ->
    {noreply, State}.

-spec cancel_timer(undefined | reference()) -> term().
cancel_timer(undefined) ->
    undefined;
cancel_timer(TimerRef) ->
    _ = erlang:cancel_timer(TimerRef, [{async, true}, {info, false}]).

-spec handle_worker_timeout(pid(), reference(), state()) -> {noreply, state()}.
handle_worker_timeout(WorkerPid, TimerRef, #state{active_workers = ActiveWorkers} = State) ->
    case maps:get(WorkerPid, ActiveWorkers, undefined) of
        #request{request_bin = RequestBin, timeout_timer = TimerRef} ->
            % Worker is still alive and timer matches, kill it and send SERVFAIL
            % We don't remove it from the active_workers because the kill will send an EXIT signal
            exit(WorkerPid, kill),
            send_servfail_response(State, RequestBin, WorkerPid),
            handle_process_buffer(State);
        _ ->
            % Worker already finished, timer was stale, worker was restarted, or timer was cancelled
            {noreply, State}
    end.

-spec send_servfail_response(state(), dns:message_bin(), pid()) -> term().
send_servfail_response(#state{socket = Socket, socket_type = SocketType}, RequestBin, WorkerPid) ->
    try
        Decoded = dns:decode_query(RequestBin),
        % Try to log the qname of the query that
        #dns_message{questions = [#dns_query{name = QName, type = QType} | _]} = Decoded,
        Metadata = #{
            what => request_timeout,
            transport => tcp,
            timeout_type => worker,
            worker_pid => WorkerPid,
            qname => QName,
            qtype => QType
        },
        telemetry:execute([erldns, request, timeout], #{count => 1}, Metadata),
        ?LOG_WARNING(Metadata, ?LOG_METADATA),
        ServfailMsg = erldns_encoder:build_error_response(Decoded),
        EncodedResponse = dns:encode_message(ServfailMsg),
        Payload = [<<(byte_size(EncodedResponse)):16>>, EncodedResponse],
        send_data(Socket, SocketType, Payload)
    catch
        Class:Reason:Stacktrace ->
            ExceptionMetadata = #{
                what => send_servfail_failed,
                transport => tcp,
                kind => Class,
                reason => Reason,
                stacktrace => Stacktrace
            },
            TimeoutMetadata = #{transport => tcp, pid => WorkerPid, timeout_type => worker},
            telemetry:execute([erldns, request, timeout], #{count => 1}, TimeoutMetadata),
            telemetry:execute([erldns, request, error], #{count => 1}, ExceptionMetadata)
    end.

-spec send_data(socket(), socket_type(), iodata()) -> ok | {error, term()}.
send_data(Socket, tcp, Data) ->
    gen_tcp:send(Socket, Data);
send_data(Socket, ssl, Data) ->
    ssl:send(Socket, Data).

-spec shutdown(state()) -> ok.
shutdown(#state{socket = Socket, socket_type = SocketType, active_workers = ActiveWorkers}) ->
    maps:foreach(
        fun(Pid, RequestInfo) ->
            cancel_timer(RequestInfo#request.timeout_timer),
            exit(Pid, kill)
        end,
        ActiveWorkers
    ),
    close_socket(Socket, SocketType).

-spec get_peername(socket(), socket_type()) ->
    {ok, {inet:ip_address(), inet:port_number()}} | {error, term()}.
get_peername(Socket, tcp) ->
    inet:peername(Socket);
get_peername(Socket, ssl) ->
    ssl:peername(Socket).

-spec close_socket(socket(), socket_type()) -> ok.
close_socket(Socket, tcp) ->
    gen_tcp:close(Socket);
close_socket(Socket, ssl) ->
    ssl:close(Socket).

-spec set_socket_active(socket(), socket_type()) -> ok.
set_socket_active(Socket, tcp) ->
    inet:setopts(Socket, [{active, once}]);
set_socket_active(Socket, ssl) ->
    ssl:setopts(Socket, [{active, once}]).

-spec detect_socket_type(module()) -> tcp | ssl.
detect_socket_type(ranch_tcp) -> tcp;
detect_socket_type(ranch_ssl) -> ssl.
