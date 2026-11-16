-module(erldns_zone_pipeline_worker).
-moduledoc false.

-behaviour(gen_server).

-include_lib("kernel/include/logger.hrl").

-export([start_link/0, init/1, handle_call/3, handle_cast/2, terminate/2]).

-spec start_link() -> gen_server:start_ret().
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, noargs, [{hibernate_after, 0}]).

-spec init(noargs) -> {ok, nostate}.
init(noargs) ->
    process_flag(trap_exit, true),
    Pipes = erldns_zone_pipeline:configured(),
    ok = erldns_zone_pipeline:store(Pipes),
    {ok, nostate}.

-spec handle_call(dynamic(), gen_server:from(), nostate) -> {reply, not_implemented, nostate}.
handle_call(Call, From, nostate) ->
    ?LOG_INFO(#{what => unexpected_call, from => From, call => Call}, #{domain => [erldns, zones]}),
    {reply, not_implemented, nostate}.

-spec handle_cast(dynamic(), nostate) -> {noreply, nostate}.
handle_cast(Cast, nostate) ->
    ?LOG_INFO(#{what => unexpected_cast, cast => Cast}, #{domain => [erldns, zones]}),
    {noreply, nostate}.

-spec terminate(term(), nostate) -> term().
terminate(_, nostate) ->
    erldns_zone_pipeline:delete().
