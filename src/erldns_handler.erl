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

-module(erldns_handler).
-moduledoc """
The module that handles the resolution of a single DNS question.

The meat of the resolution occurs in erldns_resolver:resolve/3
""".

-behaviour(gen_server).

-include_lib("kernel/include/logger.hrl").

-define(DEFAULT_HANDLER_VERSION, 1).
-define(TIMEOUT, 5000).

-export([
    start_link/0,
    register_handler/2,
    register_handler/3,
    get_versioned_handlers/0
]).

-export([init/1, handle_call/3, handle_cast/2]).

-record(handlers_state, {
    handlers = [] :: [versioned_handler()]
}).
-opaque state() :: #handlers_state{}.
-type versioned_handler() :: {module(), [dns:type()], integer()}.
-type handler() :: {module(), [dns:type()]}.
-export_type([state/0, versioned_handler/0, handler/0]).

-doc "Start the handler registry process".
-spec start_link() -> gen_server:start_ret().
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, noargs, [{hibernate_after, 1000}]).

-doc "Register a record handler with the default version of 1".
-spec register_handler([dns:type()], module()) -> ok.
register_handler(RecordTypes, Module) ->
    register_handler(RecordTypes, Module, ?DEFAULT_HANDLER_VERSION).

-doc "Register a record handler with version".
-spec register_handler([dns:type()], module(), integer()) -> ok.
register_handler(RecordTypes, Module, Version) ->
    gen_server:call(?MODULE, {register_handler, RecordTypes, Module, Version}, ?TIMEOUT).

-doc "Get all registered handlers along with the DNS types they handle and associated versions".
-spec get_versioned_handlers() -> [versioned_handler()].
get_versioned_handlers() ->
    ets:lookup_element(?MODULE, handlers, 2, []).

% gen_server callbacks
-doc false.
-spec init(noargs) -> {ok, state()}.
init(noargs) ->
    ets:new(?MODULE, [named_table, protected, set, {read_concurrency, true}]),
    {ok, #handlers_state{}}.

-doc false.
-spec handle_call
    ({register_handler, [dns:type()], module(), integer()}, gen_server:from(), state()) ->
        {reply, ok, state()};
    (dynamic(), gen_server:from(), state()) ->
        {reply, not_implemented, state()}.
handle_call({register_handler, RecordTypes, Module, Version}, _, State) ->
    ?LOG_INFO(
        #{what => registered_handler, module => Module, types => RecordTypes, version => Version},
        #{domain => [erldns, pipeline]}
    ),
    NewHandlers = [{Module, RecordTypes, Version} | State#handlers_state.handlers],
    ets:insert(?MODULE, {handlers, NewHandlers}),
    {reply, ok, State#handlers_state{handlers = NewHandlers}};
handle_call(_, _, State) ->
    {reply, not_implemented, State}.

-doc false.
-spec handle_cast(term(), state()) -> {noreply, state()}.
handle_cast(_, State) ->
    {noreply, State}.
