%% Copyright (c) 2012-2018, DNSimple Corporation
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

%% @doc Public API for erldns event handler registration and notification.
-module(erldns_events).

-export([start_link/0, notify/1, add_handler/1, add_handler/2]).

%% @doc Start the event process.
-spec start_link() -> any().
start_link() ->
  gen_event:start_link({local, ?MODULE}).

%% @doc Fire an event.
-spec notify(any()) -> any().
notify(Event) ->
  gen_event:notify(?MODULE, Event).

%% @doc Add an event handler.
-spec add_handler(module()) -> any().
add_handler(Module) ->
  add_handler(Module, []).

%% @doc Add an event handler with arguments.
-spec add_handler(module(), [term()]) -> any().
add_handler(Module, Args) ->
  gen_event:add_handler(?MODULE, Module, Args).
