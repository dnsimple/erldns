-module(erldns_proto_udp_sup).
-moduledoc false.

-behaviour(supervisor).

-export([start_link/3, init/1]).

-spec start_link(erldns_listeners:name(), erldns_listeners:p_factor(), [gen_udp:option()]) ->
    supervisor:startlink_ret().
start_link(Name, PFactor, SocketOpts) ->
    supervisor:start_link(?MODULE, {Name, PFactor, SocketOpts}).

-spec init({erldns_listeners:name(), erldns_listeners:p_factor(), [gen_udp:option()]}) ->
    {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init({Name, PFactor, SocketOpts}) ->
    proc_lib:set_label({?MODULE, Name}),
    SupFlags = #{strategy => rest_for_one},
    Children = child_specs(Name, PFactor, SocketOpts),
    {ok, {SupFlags, Children}}.

child_specs(Name, PFactor, SocketOpts) ->
    Timeout = erldns_config:ingress_udp_request_timeout(),
    SchedulersNum = erlang:system_info(schedulers),
    WorkersName = name(Name, erldns_proto_udp),
    AcceptorsName = name(Name, erldns_proto_udp_acceptor),
    NumAcceptors = PFactor * SchedulersNum,
    NumWorkers = 8 * PFactor * SchedulersNum,
    WorkersPool = workers(WorkersName, NumWorkers, Timeout),
    AcceptorsPool = acceptors(AcceptorsName, WorkersName, NumAcceptors, SocketOpts, Timeout),
    [WorkersPool, AcceptorsPool].

workers(WorkersName, NumWorkers, Timeout) ->
    WorkerOpts = #{
        workers => NumWorkers,
        worker => {erldns_proto_udp, noargs},
        worker_opt => [],
        worker_shutdown => timer:seconds(1) + Timeout,
        pool_sup_shutdown => infinity,
        strategy => #{
            strategy => one_for_one,
            intensity => 1 + ceil(math:log2(NumWorkers)),
            period => 5
        },
        overrun_warning => Timeout,
        overrun_handler => [{erldns_proto_udp, overrun_handler}],
        max_overrun_warnings => 2
    },
    wpool:child_spec(WorkersName, WorkerOpts).

acceptors(AceptorsName, WorkersName, NumAcceptors, SocketOpts, Timeout) ->
    AcceptorOpts = #{
        workers => NumAcceptors,
        worker => {erldns_proto_udp_acceptor, {WorkersName, SocketOpts}},
        worker_opt => [],
        worker_shutdown => Timeout,
        pool_sup_shutdown => infinity,
        strategy => #{
            strategy => one_for_one,
            intensity => 1 + ceil(math:log2(NumAcceptors)),
            period => 5
        }
    },
    wpool:child_spec(AceptorsName, AcceptorOpts).

%% This is done only at startup so it won't create more atoms than it was configured to
name(Name, Type) ->
    list_to_atom(atom_to_list(Name) ++ "_" ++ atom_to_list(Type)).
