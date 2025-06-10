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

-module(erldns_sup).
-moduledoc false.

-behaviour(supervisor).

-export([start_link/0]).
-export([gc/0, gc_registered/0, gc_registered/1]).

-export([init/1]).

%% Public API
-spec start_link() -> supervisor:startlink_ret().
start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

%% Garbage collect all processes.
-spec gc() -> integer().
gc() ->
    length(lists:map(fun erlang:garbage_collect/1, processes())).

%% Garbage collect all registered processes.
-spec gc_registered() -> integer().
gc_registered() ->
    length(lists:map(fun gc_registered/1, registered())).

%% Garbage collect a named process.
-spec gc_registered(atom()) -> ok.
gc_registered(ProcessName) ->
    Pid = whereis(ProcessName),
    erlang:garbage_collect(Pid),
    ok.

%% Callbacks
init(_Args) ->
    Children =
        [
            worker(erldns_pg, pg, [erldns]),
            worker(erldns_zone_cache),
            worker(erldns_zone_parser),
            worker(erldns_zone_loader),
            worker(erldns_zone_encoder),
            worker(erldns_packet_cache),
            worker(erldns_query_throttle),
            worker(erldns_handler),
            worker(erldns_pipeline),
            supervisor(erldns_listeners)
        ],
    {ok, {#{strategy => one_for_one, intensity => 20, period => 10}, Children}}.

worker(Name) ->
    worker(Name, Name, []).
worker(Name, Module, Args) ->
    child(worker, Name, Module, Args).

supervisor(Name) ->
    child(supervisor, Name, Name, []).

child(Type, Name, Module, Args) ->
    #{id => Name, start => {Module, start_link, Args}, type => Type}.
