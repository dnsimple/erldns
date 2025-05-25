%% Copyright (c) 2012-2025, DNSimple Corporation
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

%% @doc Example middleware for erldns admin API.
%%
%% This is a simple example middleware that demonstrates how to create
%% custom middleware for the erldns admin API. This middleware adds a
%% custom header to all responses.
-module(example_middleware).
-moduledoc """
Example middleware for erldns admin API.

This middleware adds a custom header 'X-Admin-Middleware' to all responses
to demonstrate how custom middleware can be integrated.

To use this middleware, add it to your sys.config:
```erlang
{erldns, [
    {admin, [
        {credentials, {<<"username">>, <<"password">>}},
        {port, 8083},
        {middleware, [example_middleware]}
    ]}
]}
```
""".

-behaviour(cowboy_middleware).

-export([execute/2]).

-include_lib("kernel/include/logger.hrl").

%% @doc Execute the middleware
-spec execute(cowboy_req:req(), cowboy_middleware:env()) ->
    {ok, cowboy_req:req(), cowboy_middleware:env()}
    | {stop, cowboy_req:req()}.
execute(Req, Env) ->
    ?LOG_DEBUG(#{what => example_middleware_executed, path => cowboy_req:path(Req)}),

    % Add a custom header to the response
    Req2 = cowboy_req:set_resp_header(<<"x-admin-middleware">>, <<"active">>, Req),

    {ok, Req2, Env}.
