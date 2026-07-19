-module(config_SUITE).
-compile([export_all, nowarn_export_all]).

-behaviour(ct_suite).

-include_lib("stdlib/include/assert.hrl").

-define(WILDCARD, [{port, 0}, inet6, {ipv6_v6only, false}, {ip, any}]).
-define(DUAL_STACK, [{port, 0}, inet6, {ipv6_v6only, false}, {ip, any}, {reuseport, true}]).
%% Windows shares no ports, so it runs one socket and needs no reuse options.
-define(IPV4_ONLY_WIN, [inet, {port, 0}, {ip, any}]).
-define(IPV4_ONLY_BSD, [inet, {port, 0}, {ip, any}, {reuseport, true}]).

-spec all() -> [ct_suite:ct_test_def()].
all() ->
    [
        dual_stack_platforms_keep_ipv6,
        windows_and_openbsd_fall_back_to_ipv4,
        reuseport_lb_only_on_freebsd,
        explicit_family_is_never_rewritten,
        caller_options_are_not_overridden,
        transform_is_idempotent,
        host_options_actually_bind,
        socket_count_capped_on_windows,
        dual_stack_is_split_only_on_freebsd
    ].

dual_stack_platforms_keep_ipv6(_) ->
    ?assertEqual(?DUAL_STACK, erldns_config:socket_opts(?WILDCARD, {unix, linux})),
    ?assertEqual(?DUAL_STACK, erldns_config:socket_opts(?WILDCARD, {unix, darwin})),
    %% An unknown platform keeps today's behaviour rather than silently losing IPv6.
    ?assertEqual(?DUAL_STACK, erldns_config:socket_opts(?WILDCARD, {unix, netbsd})).

windows_and_openbsd_fall_back_to_ipv4(_) ->
    ?assertEqual(?IPV4_ONLY_WIN, erldns_config:socket_opts(?WILDCARD, {win32, nt})),
    ?assertEqual(?IPV4_ONLY_BSD, erldns_config:socket_opts(?WILDCARD, {unix, openbsd})).

reuseport_lb_only_on_freebsd(_) ->
    %% Asking for both leaves the classic, non-balancing option in charge.
    FreeBsd = erldns_config:socket_opts(?WILDCARD, {unix, freebsd}),
    ?assert(lists:member({reuseport_lb, true}, FreeBsd)),
    ?assertNot(lists:keymember(reuseport, 1, FreeBsd)),
    %% DragonFly balances under the plain name and has no SO_REUSEPORT_LB, so
    %% requesting one would be the same mistake in the other direction.
    ?assert(
        lists:member({reuseport, true}, erldns_config:socket_opts(?WILDCARD, {unix, dragonfly}))
    ),
    lists:foreach(
        fun(OsType) ->
            Opts = erldns_config:socket_opts(?WILDCARD, OsType),
            ?assertNot(lists:keymember(reuseport_lb, 1, Opts), OsType)
        end,
        [
            {unix, linux},
            {unix, darwin},
            {unix, openbsd},
            {unix, netbsd},
            {unix, dragonfly},
            {win32, nt}
        ]
    ).

explicit_family_is_never_rewritten(_) ->
    %% Only a dual-stack wildcard is adjusted; a named family survives everywhere.
    V6 = [{port, 53}, inet6, {ip, {0, 0, 0, 0, 0, 0, 0, 1}}],
    V4 = [{port, 53}, inet, {ip, {127, 0, 0, 1}}],
    lists:foreach(
        fun(OsType) ->
            ?assertEqual(V6, strip_reuse(erldns_config:socket_opts(V6, OsType)), OsType),
            ?assertEqual(V4, strip_reuse(erldns_config:socket_opts(V4, OsType)), OsType)
        end,
        [{unix, linux}, {unix, openbsd}, {win32, nt}]
    ).

caller_options_are_not_overridden(_) ->
    %% A caller that already decided about port reuse keeps its own value.
    Requested = [{port, 0}, inet, {reuseport, false}, {reuseport_lb, false}],
    ?assertEqual(Requested, erldns_config:socket_opts(Requested, {unix, freebsd})).

transform_is_idempotent(_) ->
    lists:foreach(
        fun(OsType) ->
            Once = erldns_config:socket_opts(?WILDCARD, OsType),
            ?assertEqual(Once, erldns_config:socket_opts(Once, OsType), OsType)
        end,
        [{unix, linux}, {unix, freebsd}, {unix, openbsd}, {win32, nt}]
    ).

host_options_actually_bind(_) ->
    %% Turns the tables above into a verified fact on every platform CI runs on.
    Opts = erldns_config:socket_opts(?WILDCARD, os:type()) -- [{port, 0}],
    {ok, Udp} = gen_udp:open(0, [binary, {active, false} | Opts]),
    ok = gen_udp:close(Udp),
    {ok, Tcp} = gen_tcp:listen(0, [binary, {active, false} | Opts]),
    ok = gen_tcp:close(Tcp).

strip_reuse(Opts) ->
    Opts -- [{reuseport, true}, {reuseport_lb, true}].

socket_count_capped_on_windows(_) ->
    ?assertEqual(1, erldns_config:socket_count(8, {win32, nt})),
    lists:foreach(
        fun(OsType) -> ?assertEqual(8, erldns_config:socket_count(8, OsType), OsType) end,
        [{unix, linux}, {unix, freebsd}, {unix, openbsd}, {unix, darwin}]
    ).

dual_stack_is_split_only_on_freebsd(_) ->
    %% FreeBSD does not balance v4-mapped traffic on a dual-stack socket, so the
    %% acceptors take a family each instead.
    Tuned = fun(OsType) -> erldns_config:socket_opts(?WILDCARD, OsType) end,
    ?assertEqual(
        [
            [inet, {ip, any}, {port, 0}, {reuseport_lb, true}],
            [inet6, {ipv6_v6only, true}, {ip, any}, {port, 0}, {reuseport_lb, true}]
        ],
        erldns_config:split_socket_opts(Tuned({unix, freebsd}), {unix, freebsd})
    ),
    %% Everywhere else one socket serves both families, or the platform never
    %% asked for a dual-stack one in the first place.
    lists:foreach(
        fun(OsType) ->
            Opts = Tuned(OsType),
            ?assertEqual([Opts], erldns_config:split_socket_opts(Opts, OsType), OsType)
        end,
        [
            {unix, linux},
            {unix, darwin},
            {unix, openbsd},
            {unix, netbsd},
            {unix, dragonfly},
            {win32, nt}
        ]
    ),
    %% An explicitly addressed listener is never split.
    V4 = [{port, 53}, inet, {ip, {127, 0, 0, 1}}],
    ?assertEqual([V4], erldns_config:split_socket_opts(V4, {unix, freebsd})).
