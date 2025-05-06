%% Copyright (c) 2012-2020, DNSimple Corporation
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

%% @doc Worker module that asynchronously accepts a single DNS packet and
%% hands it to a worker process that has a set timeout.
-module(erldns_worker).

-include_lib("dns_erlang/include/dns.hrl").
-include_lib("kernel/include/logger.hrl").

-behaviour(gen_server).

-export([start_link/1]).
-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3
]).

-record(state, {worker_process_sup, worker_process}).

start_link(Args) ->
    gen_server:start_link(?MODULE, Args, []).

init([WorkerId]) ->
    {ok, WorkerProcessSup} = erldns_worker_process_sup:start_link([WorkerId]),
    WorkerProcess = lists:last(supervisor:which_children(WorkerProcessSup)),
    {ok, #state{worker_process_sup = WorkerProcessSup, worker_process = WorkerProcess}}.

handle_call(_Request, From, State) ->
    ?LOG_DEBUG("Received unexpected call (from: ~p)", [From]),
    {reply, ok, State}.

handle_cast({tcp_query, Socket, Bin}, State) ->
    case handle_tcp_dns_query(Socket, Bin, {State#state.worker_process_sup, State#state.worker_process}) of
        ok ->
            {noreply, State};
        {error, timeout, NewWorkerPid} ->
            {Id, _, Type, Modules} = State#state.worker_process,
            {noreply, State#state{worker_process = {Id, NewWorkerPid, Type, Modules}}};
        Error ->
            ?LOG_ERROR("Error handling TCP query (module: ~p, event: ~p, error: ~p)", [?MODULE, handle_tcp_query_error, Error]),
            {noreply, State}
    end;
handle_cast({udp_query, Socket, Host, Port, Bin}, State) ->
    case handle_udp_dns_query(Socket, Host, Port, Bin, {State#state.worker_process_sup, State#state.worker_process}) of
        ok ->
            {noreply, State};
        {error, timeout, NewWorkerPid} ->
            {Id, _, Type, Modules} = State#state.worker_process,
            {noreply, State#state{worker_process = {Id, NewWorkerPid, Type, Modules}}};
        Error ->
            ?LOG_ERROR("Error handling UDP query (module: ~p, event: ~p, error: ~p)", [?MODULE, handle_udp_query_error, Error]),
            {noreply, State}
    end;
handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% @doc Handle DNS query that comes in over TCP
-spec handle_tcp_dns_query(gen_tcp:socket(), iodata(), {pid(), term()}) ->
    ok | {error, timeout} | {error, timeout, pid()}.
handle_tcp_dns_query(Socket, <<_Len:16, Bin/binary>>, {WorkerProcessSup, WorkerProcess}) ->
    case inet:peername(Socket) of
        {ok, {Address, _Port}} ->
            try
                case Bin of
                    <<>> ->
                        ok;
                    _ ->
                        case erldns_decoder:decode_message(Bin) of
                            {trailing_garbage, DecodedMessage, TrailingGarbage} ->
                                ?LOG_INFO(
                                    "Decoded message included trailing garbage (module: ~p, event: ~p, message: ~p, garbage: ~p)",
                                    [?MODULE, decode_message_trailing_garbage, DecodedMessage, TrailingGarbage]
                                ),
                                handle_decoded_tcp_message(
                                    DecodedMessage, Socket, Address, {WorkerProcessSup, WorkerProcess}
                                );
                            {Error, Message, _} ->
                                ?LOG_ERROR(
                                    "Error decoding message (module: ~p, event: ~p, error: ~p, message: ~p)",
                                    [?MODULE, decode_message_error, Error, Message]
                                ),
                                ok;
                            DecodedMessage ->
                                handle_decoded_tcp_message(
                                    DecodedMessage, Socket, Address, {WorkerProcessSup, WorkerProcess}
                                )
                        end
                end
            of
                Result ->
                    folsom_metrics:notify({tcp_request_meter, 1}),
                    folsom_metrics:notify({tcp_request_counter, {inc, 1}}),
                    Result
            catch
                Exception:Reason ->
                    folsom_metrics:notify({tcp_error_meter, 1}),
                    folsom_metrics:notify({tcp_error_history, Reason}),
                    {error, Exception, Reason}
            after
                gen_tcp:close(Socket)
            end;
        {error, Reason} ->
            ?LOG_DEBUG("Notifying error reason: ~p", [Reason]),
            folsom_metrics:notify({tcp_error_meter, 1}),
            folsom_metrics:notify({tcp_error_history, Reason})
    end;
handle_tcp_dns_query(Socket, BadPacket, _) ->
    ?LOG_ERROR("Received bad packet (module: ~p, event: ~p, protocol: ~p, packet: ~p)", [?MODULE, bad_packet, tcp, BadPacket]),
    gen_tcp:close(Socket).

handle_decoded_tcp_message(DecodedMessage, Socket, Address, {WorkerProcessSup, {WorkerProcessId, WorkerProcessPid, _, _}}) ->
    case DecodedMessage#dns_message.qr of
        false ->
            try
                gen_server:call(
                    WorkerProcessPid,
                    {process, DecodedMessage, Socket, {tcp, Address}},
                    _Timeout = erldns_config:ingress_tcp_request_timeout()
                )
            of
                _ ->
                    ok
            catch
                exit:{timeout, _} ->
                    folsom_metrics:notify({worker_timeout_counter, {inc, 1}}),
                    folsom_metrics:notify({worker_timeout_meter, 1}),
                    handle_timeout(WorkerProcessSup, WorkerProcessId);
                Error:Reason ->
                    ?LOG_ERROR(
                        "Worker process crashed (module: ~p, event: ~p, protocol: ~p, error: ~p, reason: ~p, message: ~p)",
                        [?MODULE, process_crashed, tcp, Error, Reason, DecodedMessage]
                    ),
                    {error, {Error, Reason}}
            end;
        true ->
            {error, not_a_question}
    end.

%% @doc Handle DNS query that comes in over UDP
-spec handle_udp_dns_query(gen_udp:socket(), gen_udp:ip(), inet:port_number(), binary(), {pid(), term()}) ->
    ok | {error, not_owner | timeout | inet:posix() | atom()} | {error, timeout, pid()}.
handle_udp_dns_query(Socket, Host, Port, Bin, {WorkerProcessSup, WorkerProcess}) ->
    Result =
        case erldns_decoder:decode_message(Bin) of
            {trailing_garbage, DecodedMessage, TrailingGarbage} ->
                ?LOG_INFO(
                    "Decoded message included trailing garbage (module: ~p, event: ~p, message: ~p, garbage: ~p)",
                    [?MODULE, decode_message_trailing_garbage, DecodedMessage, TrailingGarbage]
                ),
                handle_decoded_udp_message(DecodedMessage, Socket, Host, Port, {WorkerProcessSup, WorkerProcess});
            {Error, Message, _} ->
                ?LOG_ERROR("Error decoding message (module: ~p, event: ~p, error: ~p, message: ~p)", [
                    ?MODULE, decode_message_error, Error, Message
                ]),
                ok;
            DecodedMessage ->
                handle_decoded_udp_message(DecodedMessage, Socket, Host, Port, {WorkerProcessSup, WorkerProcess})
        end,
    folsom_metrics:notify({udp_request_meter, 1}),
    folsom_metrics:notify({udp_request_counter, {inc, 1}}),
    Result.

-spec handle_decoded_udp_message(dns:message(), gen_udp:socket(), gen_udp:ip(), inet:port_number(), {
    pid(), term()
}) ->
    ok | {error, not_owner | timeout | inet:posix() | atom()} | {error, timeout, term()}.
handle_decoded_udp_message(DecodedMessage, Socket, Host, Port, {WorkerProcessSup, {WorkerProcessId, WorkerProcessPid, _, _}}) ->
    case DecodedMessage#dns_message.qr of
        false ->
            try
                gen_server:call(
                    WorkerProcessPid,
                    {process, DecodedMessage, Socket, Port, {udp, Host}},
                    _Timeout = erldns_config:ingress_udp_request_timeout()
                )
            of
                _ ->
                    ok
            catch
                exit:{timeout, _} ->
                    ?LOG_INFO("Worker timeout (module: ~p, event: ~p, protocol: ~p, message: ~p)", [
                        ?MODULE, timeout, udp, DecodedMessage
                    ]),
                    folsom_metrics:notify({worker_timeout_counter, {inc, 1}}),
                    folsom_metrics:notify({worker_timeout_meter, 1}),
                    handle_timeout(WorkerProcessSup, WorkerProcessId);
                Error:Reason ->
                    ?LOG_ERROR(
                        "Worker process crashed (module: ~p, event: ~p, protocol: ~p, error: ~p, reason: ~p, message: ~p)",
                        [?MODULE, process_crashed, udp, Error, Reason, DecodedMessage]
                    ),
                    {error, {Error, Reason}}
            end;
        true ->
            {error, not_a_question}
    end.

-spec handle_timeout(pid(), term()) -> {error, timeout, term()} | {error, timeout}.
handle_timeout(WorkerProcessSup, WorkerProcessId) ->
    TerminateResult = supervisor:terminate_child(WorkerProcessSup, WorkerProcessId),
    ?LOG_DEBUG("Terminate result: ~p", [TerminateResult]),
    case supervisor:restart_child(WorkerProcessSup, WorkerProcessId) of
        {ok, NewChild} ->
            {error, timeout, NewChild};
        {ok, NewChild, _} ->
            {error, timeout, NewChild};
        {error, Error} ->
            ?LOG_ERROR(
                "Restart failed (module: ~p, event: ~p, error: ~p)",
                [?MODULE, restart_failed, Error]
            ),
            {error, timeout}
    end.
