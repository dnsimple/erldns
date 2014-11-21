%%%-------------------------------------------------------------------
%%% @author kyle
%%% @copyright (C) 2014, siftlogic LLC
%%% @doc
%%%     API for any prefered storage type. Modules for the specified type should be of the form
%%%     erldns_storage_mnesia, etc...
%%% @end
%%% Created : 20. Nov 2014 3:33 PM
%%%-------------------------------------------------------------------
-module(erldns_storage).
-author("kyle").

-behaviour(gen_server).

%% API
-export([start_link/0,
         create/1,
         create/2,
         insert/2,
         delete/1,
         delete/2,
         select/0,
         lookup/2]).

%% gen_server callbacks
-export([init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3]).

-record(state, {}).

-define(POLL_WAIT_HOURS, 1).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

init([]) ->
    {ok, #state{}, 0}.

handle_call(_Request, _From, State) ->
    {reply, ok, State, 0}.

handle_cast(_Msg, State) ->
    {noreply, State, 0}.

handle_info(timeout, State) ->
    Before = now(),
    backup(),
    TimeSpentMs = timer:now_diff(now(), Before) div 1000,
    {noreply, State, max((?POLL_WAIT_HOURS * 60000) - TimeSpentMs, 0)};
handle_info(_Info, State) ->
    {noreply, State, 0}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

create(Key) ->
    not_implemented.

create(Key, Options) ->
    not_implemented.

insert(Key, Value)->
    not_implemented.

delete(Key)->
    not_implemented.

delete(Key, Value)->
    not_implemented.

select()->
    not_implemented.

backup()->
    not_implemented.

lookup(Key, Value) ->
    not_implemented.