-module(erldns_proto_udp_sup).
-moduledoc false.

-define(MIN_HEAP_SIZE, 650).

-behaviour(supervisor).

-export([start_link/4, init/1]).

-spec start_link(
    erldns_listeners:name(),
    erldns_listeners:parallel_factor(),
    non_neg_integer(),
    [gen_udp:option()]
) -> supervisor:startlink_ret().
start_link(Name, PFactor, Timeout, SocketOpts) ->
    supervisor:start_link(?MODULE, {Name, PFactor, Timeout, SocketOpts}).

-spec init(
    {erldns_listeners:name(), erldns_listeners:parallel_factor(), non_neg_integer(), [
        gen_udp:option()
    ]}
) ->
    {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init({Name, PFactor, Timeout, SocketOpts}) ->
    proc_lib:set_label({?MODULE, Name}),
    SupFlags = #{strategy => rest_for_one},
    Children = child_specs(Name, PFactor, Timeout, SocketOpts),
    {ok, {SupFlags, Children}}.

child_specs(Name, PFactor, Timeout, SocketOpts) ->
    SchedulersNum = erlang:system_info(schedulers),
    WorkersName = name(Name, erldns_proto_udp),
    NumAcceptors = PFactor * SchedulersNum,
    NumWorkers = 8 * PFactor * SchedulersNum,
    WorkersPool = workers(WorkersName, NumWorkers, Timeout),
    AcceptorsPool = acceptors(WorkersName, NumAcceptors, Timeout, SocketOpts),
    [WorkersPool, AcceptorsPool].

workers(WorkersName, NumWorkers, Timeout) ->
    WorkerOpts = #{
        workers => NumWorkers,
        worker => {erldns_proto_udp, Timeout},
        worker_opt => [{min_heap_size, ?MIN_HEAP_SIZE}],
        worker_shutdown => timer:seconds(1) + Timeout,
        pool_sup_shutdown => infinity,
        strategy => #{
            strategy => one_for_one,
            intensity => 1 + ceil(math:log2(NumWorkers)),
            period => 5
        },
        overrun_warning => Timeout,
        overrun_handler => [{erldns_proto_udp, overrun_handler}],
        max_overrun_warnings => 2,
        enable_queues => false
    },
    wpool:child_spec(WorkersName, WorkerOpts).

acceptors(WorkersName, NumAcceptors, Timeout, SocketOpts) ->
    #{
        id => erldns_proto_udp_acceptor_sup,
        start =>
            {erldns_proto_udp_acceptor_sup, start_link, [
                WorkersName, NumAcceptors, Timeout, SocketOpts
            ]},
        type => supervisor
    }.

%% This is done only at startup so it won't create more atoms than it was configured to
name(Name, Type) ->
    list_to_atom(atom_to_list(Name) ++ "_" ++ atom_to_list(Type)).
