-module(erldns_proto_udp_acceptor_sup).
-moduledoc false.

-behaviour(supervisor).

-export([start_link/4, init/1]).

-spec start_link(erldns_listeners:name(), non_neg_integer(), timeout(), [gen_udp:option()]) ->
    supervisor:startlink_ret().
start_link(WorkersName, NumAcceptors, Timeout, SocketOpts) ->
    supervisor:start_link(?MODULE, {WorkersName, NumAcceptors, Timeout, SocketOpts}).

-spec init({erldns_listeners:name(), non_neg_integer(), timeout(), [gen_udp:option()]}) ->
    {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init({WorkersName, NumAcceptors, Timeout, SocketOpts}) ->
    Strategy = #{
        strategy => one_for_one,
        intensity => 1 + ceil(math:log2(NumAcceptors)),
        period => 5
    },
    Acceptors = [
        #{
            id => {erldns_proto_udp_acceptor, N},
            start => {erldns_proto_udp_acceptor, start_link, [WorkersName, Timeout, SocketOpts]},
            shutdown => Timeout,
            type => worker
        }
     || N <- lists:seq(1, NumAcceptors)
    ],
    {ok, {Strategy, Acceptors}}.
