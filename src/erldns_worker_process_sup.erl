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

%% @doc Supervisor that allows terminate and restart of an erldns_worker_process
%% that is attached to an erldns_worker.
-module(erldns_worker_process_sup).

-behavior(supervisor).

-export([start_link/1]).

-export([init/1]).

start_link([WorkerId]) ->
  % This supervisor is registered without a name. An alternative
  % if a name is necessary is to create an atom() using the WorkerId
  % value combined with the module name
  supervisor:start_link(?MODULE, [WorkerId]).

init(WorkerId) ->
  {ok, {{one_for_one, 20, 10}, [{{WorkerId, erldns_worker_process}, {erldns_worker_process, start_link, [[]]}, permanent, brutal_kill, worker, [erldns_worker_process]}]}}. 
