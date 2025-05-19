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

%% @doc The erldns OTP application.
-module(erldns_app).

-include_lib("kernel/include/logger.hrl").

-behaviour(application).

% Application hooks
-export([
    start/2,
    start_phase/3,
    stop/1
]).

start(_Type, _Args) ->
    ?LOG_INFO("Starting erldns application"),
    nodefinder:multicast_start(),
    Ret = erldns_sup:start_link(),
    erldns_admin:maybe_start(),
    Ret.

start_phase(post_start, _StartType, _PhaseArgs) ->
    case application:get_env(erldns, custom_zone_parsers) of
        {ok, Parsers} ->
            erldns_zone_parser:register_parsers(Parsers);
        _ ->
            ok
    end,

    case application:get_env(erldns, custom_zone_encoders) of
        {ok, Encoders} ->
            erldns_zone_encoder:register_encoders(Encoders);
        _ ->
            ok
    end,

    ?LOG_INFO("Loading zones from local file"),
    erldns_zone_loader:load_zones(),

    % Start up the UDP and TCP servers
    ?LOG_INFO("Starting the UDP and TCP supervisor"),
    supervisor:start_child(
        erldns_sup,
        #{
            id => erldns_server_sup,
            start => {erldns_server_sup, start_link, []},
            restart => permanent,
            shutdown => infinity,
            type => supervisor
        }
    ),

    ok.

stop(_State) ->
    ?LOG_INFO("Stop erldns application"),
    ok.
