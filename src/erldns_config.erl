-module(erldns_config).
-moduledoc "Provide application-wide configuration access.".

-export([
    use_root_hints/0,
    socket_opts/2,
    split_socket_opts/1,
    split_socket_opts/2,
    balances_load/0,
    socket_count/1,
    socket_count/2
]).

-doc "Use IANA DNS root servers as hints".
-spec use_root_hints() -> boolean().
use_root_hints() ->
    case application:get_env(erldns, use_root_hints) of
        {ok, Flag} when is_boolean(Flag) ->
            Flag;
        _ ->
            true
    end.

-doc false.
-spec socket_opts([atom() | tuple()], os:type()) -> [atom() | tuple()].
socket_opts(Opts, OsType) ->
    reuse_opts(family_opts(Opts, OsType), OsType).

%% Windows and OpenBSD reject `{ipv6_v6only, false}', so a dual-stack wildcard
%% never binds there; fall back to IPv4 rather than not listening at all.
family_opts(Opts, OsType) ->
    case lists:member({ipv6_v6only, false}, Opts) andalso not supports_dual_stack(OsType) of
        true ->
            [inet | Opts -- [inet6, {ipv6_v6only, false}]];
        false ->
            Opts
    end.

%% `reuseaddr' is left to ranch and `base_udp_opts/0', which set it already;
%% ranch also rejects it as an explicit listen option.
reuse_opts(Opts, OsType) ->
    case reuse_opt(OsType) of
        none -> Opts;
        Opt -> Opts ++ [{Opt, true} || not lists:keymember(Opt, 1, Opts)]
    end.

%% On FreeBSD `SO_REUSEPORT_LB' is a distinct option from `SO_REUSEPORT', and
%% asking for both leaves the classic non-balancing one in charge: measured, all
%% traffic reaches the last socket bound. Linux maps the two onto one option and
%% DragonFly, whose implementation FreeBSD adapted, balances under the plain
%% name, so `reuseport' is right for both. Windows shares no ports at all.
reuse_opt({win32, _}) ->
    none;
reuse_opt({unix, freebsd}) ->
    reuseport_lb;
reuse_opt(_) ->
    reuseport.

supports_dual_stack({win32, _}) ->
    false;
supports_dual_stack({unix, openbsd}) ->
    false;
supports_dual_stack(_) ->
    true.

-doc false.
-spec split_socket_opts([atom() | tuple()]) -> [[atom() | tuple()]].
split_socket_opts(Opts) ->
    split_socket_opts(Opts, os:type()).

%% One option list per socket family a listener should bind. FreeBSD's
%% `SO_REUSEPORT_LB' does not balance IPv4 traffic arriving on a dual-stack
%% socket, so a wildcard listener there delivers every packet to one acceptor.
%% Giving the acceptors a family each restores balancing within both. Only
%% FreeBSD is known to need this; platforms without CI keep one socket.
-doc false.
-spec split_socket_opts([atom() | tuple()], os:type()) -> [[atom() | tuple()]].
split_socket_opts(Opts, OsType) ->
    case lists:member({ipv6_v6only, false}, Opts) andalso not balances_dual_stack(OsType) of
        true ->
            Rest = Opts -- [inet6, {ipv6_v6only, false}, {ip, any}],
            [
                [inet, {ip, any} | Rest],
                [inet6, {ipv6_v6only, true}, {ip, any} | Rest]
            ];
        false ->
            [Opts]
    end.

balances_dual_stack({unix, freebsd}) ->
    false;
balances_dual_stack(_) ->
    true.

-doc false.
-spec balances_load() -> boolean().
balances_load() ->
    balances_load(os:type()).

%% Whether the kernel spreads traffic across sockets sharing a port rather than
%% delivering all of it to one of them. These two are the platforms CI measures
%% doing so; everywhere else the extra acceptors bind but never receive.
%% DragonFly is likely to belong here, since its own implementation is the one
%% FreeBSD adapted, but nothing verifies that.
-spec balances_load(os:type()) -> boolean().
balances_load({unix, linux}) ->
    true;
balances_load({unix, freebsd}) ->
    true;
balances_load(_) ->
    false.

-doc false.
-spec socket_count(pos_integer()) -> pos_integer().
socket_count(Wanted) ->
    socket_count(Wanted, os:type()).

%% How many sockets a listener should open on one port. Windows refuses to bind
%% a second, so the extras would each fail to start rather than start smaller.
-doc false.
-spec socket_count(pos_integer(), os:type()) -> pos_integer().
socket_count(_, {win32, _}) ->
    1;
socket_count(Wanted, _) ->
    Wanted.
