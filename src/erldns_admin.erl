%% Copyright (c) 2012-2013, Aetrion LLC
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

%% @doc Process for an administrative HTTP API.
%%
%% Provides zone quering and command-and-control functionality.

-module(erldns_admin).

-behavior(gen_server).

-export([start_link/0]).
-export([is_authorized/2]).

-define(DEFAULT_PORT, 8083).

% Gen server hooks
-export([init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3
  ]).

-record(state, {}).

%% Not part of gen server

is_authorized(Req, State) ->
  case credentials() of
    {Username, Password} ->
      {ok, Auth, Req1} = cowboy_req:parse_header(<<"authorization">>, Req),
      case Auth of
        {<<"basic">>, {User = Username, Password}} ->
          {true, Req1, User};
        _ ->
          {{false, <<"Basic realm=\"erldns admin\"">>}, Req1, State}
      end;
    _ -> {{false, <<"Basic realm=\"erldns admin\"">>}, Req, State}
  end.

%% Gen server
start_link() ->
  gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

init([]) ->
  lager:debug("Starting ~p", [?MODULE]),

  Dispatch = cowboy_router:compile(
    [
      {'_', 
        [
          {"/", erldns_admin_root_handler, []},
          {"/zones/:name", erldns_admin_zone_query_handler, []},
          {"/zones/:name/:action", erldns_admin_zone_control_handler, []}
        ]
      }
    ]
  ),

  {ok, _} = cowboy:start_http(?MODULE, 10, [{port, port()}], [{env, [{dispatch, Dispatch}]}]),

  {ok, #state{}}.

handle_call(_Message, _From, State) ->
  {reply, ok, State}.
handle_cast(_, State) ->
  {noreply, State}.
handle_info(_, State) ->
  {noreply, State}.
terminate(_, _) ->
  ok.
code_change(_PreviousVersion, State, _Extra) ->
  {ok, State}.

port() ->
  proplists:get_value(port, env(), ?DEFAULT_PORT).

credentials() ->
  case proplists:get_value(credentials, env()) of
    {Username, Password} ->
      {list_to_binary(Username), list_to_binary(Password)};
    _ -> {}
  end.

env() ->
  case application:get_env(erldns, admin) of
    {ok, Env} -> Env;
    _ -> []
  end.
