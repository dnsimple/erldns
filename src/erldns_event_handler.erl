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

%% @doc Application event handler implementation.
-module(erldns_event_handler).

-include_lib("kernel/include/logger.hrl").

-behavior(gen_event).

-export([
    init/1,
    handle_event/2,
    handle_call/2,
    handle_info/2,
    code_change/3,
    terminate/2
]).

-record(state, {servers_running = false}).

init(_Args) ->
    {ok, #state{}}.

handle_event({_M, start_servers}, State) ->
    case State#state.servers_running of
        false ->
            % Start up the UDP and TCP servers
            ?LOG_INFO("Starting the UDP and TCP supervisor"),
            supervisor:start_child(
                erldns_sup,
                #{
                    id => erldns_sup,
                    start => {erldns_server_sup, start_link, []},
                    restart => permanent,
                    shutdown => 5000,
                    type => supervisor
                }
            ),
            erldns_events:notify({?MODULE, servers_started}),
            {ok, State#state{servers_running = true}};
        _ ->
            erldns_events:notify({?MODULE, servers_already_started}),
            {ok, State}
    end;
handle_event({_M, end_udp, [{host, _Host}]}, State) ->
    folsom_metrics:notify({udp_request_meter, 1}),
    folsom_metrics:notify({udp_request_counter, {inc, 1}}),
    {ok, State};
handle_event({_M, end_tcp, [{host, _Host}]}, State) ->
    folsom_metrics:notify({tcp_request_meter, 1}),
    folsom_metrics:notify({tcp_request_counter, {inc, 1}}),
    {ok, State};
handle_event({_M, udp_error, Reason}, State) ->
    folsom_metrics:notify({udp_error_meter, 1}),
    folsom_metrics:notify({udp_error_history, Reason}),
    {ok, State};
handle_event({_M, tcp_error, Reason}, State) ->
    folsom_metrics:notify({tcp_error_meter, 1}),
    folsom_metrics:notify({tcp_error_history, Reason}),
    {ok, State};
handle_event({M = erldns_storage, E = failed_zones_load, Reason}, State) ->
    ?LOG_ERROR("Failed to load zones (module: ~p, event: ~p, reason: ~p)", [M, E, Reason]),
    {ok, State};
handle_event({_M = erldns_worker, _E = timeout}, State) ->
    folsom_metrics:notify({worker_timeout_counter, {inc, 1}}),
    folsom_metrics:notify({worker_timeout_meter, 1}),
    {ok, State};
handle_event({M = erldns_worker, E = restart_failed, Error}, State) ->
    ?LOG_ERROR("Restart failed (module: ~p, event: ~p, error: ~p)", [M, E, Error]),
    {ok, State};
handle_event(_Event, State) ->
    {ok, State}.

handle_call(_Message, State) ->
    {ok, ok, State}.

handle_info(_Message, State) ->
    {ok, State}.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

terminate(_Reason, _State) ->
    ok.
