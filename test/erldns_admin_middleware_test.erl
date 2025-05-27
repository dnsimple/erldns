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

%% @doc Tests for middleware configuration in erldns_admin
-module(erldns_admin_middleware_test).

-include_lib("eunit/include/eunit.hrl").

%% Test middleware configuration parsing
middleware_config_test() ->
    % Test empty middleware list
    Env1 = [],
    ?assertEqual({true, []}, erldns_admin:middleware(Env1)),

    % Test valid middleware list
    Env2 = [{middleware, [example_middleware, another_middleware]}],
    ?assertEqual({true, [example_middleware, another_middleware]}, erldns_admin:middleware(Env2)),

    % Test invalid middleware (non-atom in list)
    Env3 = [{middleware, [example_middleware, "not_an_atom"]}],
    ?assertEqual({true, []}, erldns_admin:middleware(Env3)),

    % Test invalid middleware value (not a list)
    Env4 = [{middleware, not_a_list}],
    ?assertEqual({true, []}, erldns_admin:middleware(Env4)).
