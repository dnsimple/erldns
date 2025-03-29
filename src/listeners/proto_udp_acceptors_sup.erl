-module(proto_udp_acceptors_sup).

-behaviour(supervisor).

-export([start_link/2]).
-export([init/1]).

start_link(Parallelism, Port) ->
    supervisor:start_link(?MODULE, {Parallelism, Port}).

init({Parallelism, Port}) ->
    proc_lib:set_label(?MODULE),
    Procs = [
        begin
            #{
                id => {proto_udp_acceptor, AcceptorId},
                start => {proto_udp_acceptor, start_link, [AcceptorId, Port, self()]},
                shutdown => brutal_kill
            }
        end
     || AcceptorId <- lists:seq(1, Parallelism)
    ],
    {ok, {#{intensity => 1 + ceil(math:log2(Parallelism))}, Procs}}.
