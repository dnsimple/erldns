-module(proto_udp_wpool_acceptors_sup).

-behaviour(supervisor).

-export([start_link/3]).
-export([init/1]).

start_link(Parallelism, Port, Ref) ->
    supervisor:start_link(?MODULE, {Parallelism, Port, Ref}).

init({Parallelism, Port, Ref}) ->
    proc_lib:set_label(?MODULE),
    Procs = [
        begin
            #{
                id => {proto_udp_wpool_acceptor, AcceptorId},
                start => {proto_udp_wpool_acceptor, start_link, [AcceptorId, Port, self(), Ref]},
                shutdown => brutal_kill
            }
        end
     || AcceptorId <- lists:seq(1, Parallelism)
    ],
    {ok, {#{intensity => 1 + ceil(math:log2(Parallelism))}, Procs}}.
