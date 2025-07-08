-module(erldns_pipeline_worker).
-moduledoc false.

-behaviour(gen_server).

-export([start_link/0, init/1, handle_call/3, handle_cast/2, terminate/2]).

-spec start_link() -> gen_server:start_ret().
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, noargs, [{hibernate_after, 0}]).

-spec init(noargs) -> {ok, nostate}.
init(noargs) ->
    process_flag(trap_exit, true),
    ok = erldns_pipeline:store_pipeline(),
    {ok, nostate}.

-spec handle_call(sync, gen_server:from(), nostate) ->
    {reply, ok | not_implemented, nostate}.
handle_call(sync, _, nostate) ->
    {reply, erldns_pipeline:store_pipeline(), nostate};
handle_call(_, _, nostate) ->
    {reply, not_implemented, nostate}.

-spec handle_cast(term(), nostate) -> {noreply, nostate}.
handle_cast(_, nostate) ->
    {noreply, nostate}.

-spec terminate(term(), nostate) -> term().
terminate(_, nostate) ->
    persistent_term:erase(erldns_pipeline).
