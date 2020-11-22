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

-define(DEFAULT_UDP_PROCESS_TIMEOUT, 500).
-define(DEFAULT_TCP_PROCESS_TIMEOUT, 1000).

-behaviour(gen_server).

-export([start_link/1]).
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

-record(state, {worker_process_sup, worker_process}).

start_link(Args) ->
    gen_server:start_link(?MODULE, Args, []).

init([WorkerId]) ->
    {ok, WorkerProcessSup} = erldns_worker_process_sup:start_link([WorkerId]),
    WorkerProcess = lists:last(supervisor:which_children(WorkerProcessSup)),
    {ok, #state{worker_process_sup = WorkerProcessSup, worker_process = WorkerProcess}}.

handle_call(_Request, From, State) ->
    lager:debug("Received unexpected call (from: ~p)", [From]),
    {reply, ok, State}.

handle_cast({tcp_query, Socket, Bin}, State) ->
    case handle_tcp_dns_query(Socket, Bin, {State#state.worker_process_sup, State#state.worker_process}) of
        ok ->
            {noreply, State};
        {error, timeout, NewWorkerPid} ->
            {Id, _, Type, Modules} = State#state.worker_process,
            {noreply, State#state{worker_process = {Id, NewWorkerPid, Type, Modules}}};
        Error ->
            lager:error("Error handling TCP query (module: ~p, event: ~p, error: ~p)", [?MODULE, handle_tcp_query_error, Error]),
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
            lager:error("Error handling UDP query (module: ~p, event: ~p, error: ~p)", [?MODULE, handle_udp_query_error, Error]),
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
-spec handle_tcp_dns_query(gen_tcp:socket(), iodata(), {pid(), term()}) -> ok | {error, timeout} | {error, timeout, pid()}.
handle_tcp_dns_query(Socket, <<_Len:16, Bin/binary>>, {WorkerProcessSup, WorkerProcess}) ->
    case inet:peername(Socket) of
        {ok, {Address, _Port}} ->
            erldns_events:notify({?MODULE, start_tcp, [{host, Address}]}),
            Result =
                case Bin of
                    <<>> ->
                        ok;
                    _ ->
                        case erldns_decoder:decode_message(Bin) of
                            {trailing_garbage, DecodedMessage, TrailingGarbage} ->
                                lager:info("Decoded message included trailing garbage (module: ~p, event: ~p, message: ~p, garbage: ~p)",
                                           [?MODULE, decode_message_trailing_garbage, DecodedMessage, TrailingGarbage]),
                                % erldns_events:notify({?MODULE, decode_message_trailing_garbage, {DecodedMessage, TrailingGarbage}}),
                                handle_decoded_tcp_message(DecodedMessage, Socket, Address, {WorkerProcessSup, WorkerProcess});
                            {Error, Message, _} ->
                                lager:error("Error decoding message (module: ~p, event: ~p, error: ~p, message: ~p)",
                                            [?MODULE, decode_message_error, Error, Message]),
                                % erldns_events:notify({?MODULE, decode_message_error, {Error, Message}}),
                                ok;
                            DecodedMessage ->
                                handle_decoded_tcp_message(DecodedMessage, Socket, Address, {WorkerProcessSup, WorkerProcess})
                        end
                end,
            erldns_events:notify({?MODULE, end_tcp, [{host, Address}]}),
            gen_tcp:close(Socket),
            Result;
        {error, Reason} ->
            erldns_events:notify({?MODULE, tcp_error, Reason})
    end;
handle_tcp_dns_query(Socket, BadPacket, _) ->
    lager:error("Received bad packet (module: ~p, event: ~p, protocol: ~p, packet: ~p)", [?MODULE, bad_packet, tcp, BadPacket]),
    % erldns_events:notify({?MODULE, bad_packet, {tcp, BadPacket}}),
    gen_tcp:close(Socket).

handle_decoded_tcp_message(DecodedMessage, Socket, Address, {WorkerProcessSup, {WorkerProcessId, WorkerProcessPid, _, _}}) ->
    case DecodedMessage#dns_message.qr of
        false ->
            try gen_server:call(WorkerProcessPid, {process, DecodedMessage, Socket, {tcp, Address}}, _Timeout = ?DEFAULT_TCP_PROCESS_TIMEOUT) of
                _ ->
                    ok
            catch
                exit:{timeout, _} ->
                    erldns_events:notify({?MODULE, timeout}),
                    handle_timeout(WorkerProcessSup, WorkerProcessId);
                Error:Reason ->
                    lager:error("Worker process crashed (module: ~p, event: ~p, protocol: ~p, error: ~p, reason: ~p, message: ~p)",
                                [?MODULE, process_crashed, tcp, Error, Reason, DecodedMessage]),
                    {error, {Error, Reason}}
            end;
        true ->
            {error, not_a_question}
    end.

%% @doc Handle DNS query that comes in over UDP
-spec handle_udp_dns_query(gen_udp:socket(), gen_udp:ip(), inet:port_number(), binary(), {pid(), term()}) ->
                              ok | {error, not_owner | timeout | inet:posix() | atom()} | {error, timeout, pid()}.
handle_udp_dns_query(Socket, Host, Port, Bin, {WorkerProcessSup, WorkerProcess}) ->
    erldns_events:notify({?MODULE, start_udp, [{host, Host}]}),
    Result =
        case erldns_decoder:decode_message(Bin) of
            {trailing_garbage, DecodedMessage, TrailingGarbage} ->
                lager:info("Decoded message included trailing garbage (module: ~p, event: ~p, message: ~p, garbage: ~p)",
                           [?MODULE, decode_message_trailing_garbage, DecodedMessage, TrailingGarbage]),
                %erldns_events:notify({?MODULE, decode_message_trailing_garbage, {DecodedMessage, TrailingGarbage}}),
                handle_decoded_udp_message(DecodedMessage, Socket, Host, Port, {WorkerProcessSup, WorkerProcess});
            {Error, Message, _} ->
                lager:error("Error decoding message (module: ~p, event: ~p, error: ~p, message: ~p)", [?MODULE, decode_message_error, Error, Message]),
                % erldns_events:notify({?MODULE, decode_message_error, {Error, Message}}),
                ok;
            DecodedMessage ->
                handle_decoded_udp_message(DecodedMessage, Socket, Host, Port, {WorkerProcessSup, WorkerProcess})
        end,
    erldns_events:notify({?MODULE, end_udp, [{host, Host}]}),
    Result.

-spec handle_decoded_udp_message(dns:message(), gen_udp:socket(), gen_udp:ip(), inet:port_number(), {pid(), term()}) ->
                                    ok | {error, not_owner | timeout | inet:posix() | atom()} | {error, timeout, term()}.
handle_decoded_udp_message(DecodedMessage, Socket, Host, Port, {WorkerProcessSup, {WorkerProcessId, WorkerProcessPid, _, _}}) ->
    case DecodedMessage#dns_message.qr of
        false ->
            try gen_server:call(WorkerProcessPid, {process, DecodedMessage, Socket, Port, {udp, Host}}, _Timeout = ?DEFAULT_UDP_PROCESS_TIMEOUT) of
                _ ->
                    ok
            catch
                exit:{timeout, _} ->
                    lager:info("Worker timeout (module: ~p, event: ~p, protocol: ~p, message: ~p)", [?MODULE, timeout, udp, DecodedMessage]),
                    erldns_events:notify({?MODULE, timeout}),
                    handle_timeout(WorkerProcessSup, WorkerProcessId);
                Error:Reason ->
                    lager:error("Worker process crashed (module: ~p, event: ~p, protocol: ~p, error: ~p, reason: ~p, message: ~p)",
                                [?MODULE, process_crashed, udp, Error, Reason, DecodedMessage]),
                    % erldns_events:notify({?MODULE, process_crashed, {udp, Error, Reason, DecodedMessage}}),
                    {error, {Error, Reason}}
            end;
        true ->
            {error, not_a_question}
    end.

-spec handle_timeout(pid(), term()) -> {error, timeout, term()} | {error, timeout}.
handle_timeout(WorkerProcessSup, WorkerProcessId) ->
    TerminateResult = supervisor:terminate_child(WorkerProcessSup, WorkerProcessId),
    lager:debug("Terminate result: ~p", [TerminateResult]),

    case supervisor:restart_child(WorkerProcessSup, WorkerProcessId) of
        {ok, NewChild} ->
            {error, timeout, NewChild};
        {ok, NewChild, _} ->
            {error, timeout, NewChild};
        {error, Error} ->
            erldns_events:notify({?MODULE, restart_failed, {Error}}),
            {error, timeout}
    end.
