-module(erldns_handler).
-moduledoc """
The module that handles the resolution of a single DNS question.

The meat of the resolution occurs in erldns_resolver:resolve/3

## Configuration

```erlang
{erldns, [
    {packet_handlers, [
        {my_custom_handler_module, [?DNS_TYPE_A, ?DNS_TYPE_AAAA], 3}
    ]},
]}
```

Record types can be given in their integer codes or binary representations,
meaning, the following are equivalent:
```erlang
    {my_custom_handler_module, [?DNS_TYPE_A, ?DNS_TYPE_AAAA], 3}
    ...
    {my_custom_handler_module, [?DNS_TYPE_A, ~"AAAA"], 3}
    ...
    {my_custom_handler_module, [~"A", ~"AAAA"], 3}
```

The minimum supported version is `2`.

Version 2's handler signature is
```erlang
handle(dns:message(), dns:labels(), dns:type(), [dns:rr()]) -> [dns:rr()]
```.
Version 3's handler signature is
```erlang
handle(dns:dname(), dns:type(), [dns:rr()], dns:message()) -> [dns:rr()].
```.
""".

-behaviour(gen_server).

-include_lib("kernel/include/logger.hrl").
-include_lib("dns_erlang/include/dns.hrl").

-define(MINIMUM_HANDLER_VERSION, 2).
-define(DEFAULT_HANDLER_VERSION, 3).
-define(TIMEOUT, 5000).

-export([
    register_handler/2,
    register_handler/3,
    get_versioned_handlers/0,
    call_filters/1,
    call_handlers/4,
    call_map_nsec_rr_types/1,
    call_map_nsec_rr_types/2
]).

-export([start_link/0, init/1, handle_call/3, handle_cast/2, terminate/2]).

-record(handlers_state, {
    handlers = [] :: [versioned_handler()]
}).
-opaque state() :: #handlers_state{}.
-type versioned_handler() :: {
    fun((dns:message(), dns:labels(), dns:type(), [dns:rr()]) -> [dns:rr()]),
    fun(([dns:rr()]) -> [dns:rr()]),
    fun((dns:type(), dns:type()) -> [dns:type()]),
    module(),
    [dns:type()],
    integer()
}.
-type handler() :: {module(), [dns:type()]}.
-export_type([state/0, versioned_handler/0, handler/0]).

-doc "Filter the given record set, returning replacement records.".
-callback filter([dns:rr()]) -> [dns:rr()].
-doc "Filter out records not related to the given handler".
-callback handle(dns:message(), dns:labels(), dns:type(), [dns:rr()]) -> [dns:rr()].
-doc "Map handler's record types to NSEC bit types.".
-callback nsec_rr_type_mapper(dns:type(), dns:type()) -> [dns:type()].

-doc "Register a record handler with the default version of 1".
-spec register_handler([dns:type()], module()) -> ok.
register_handler(RecordTypes, Module) ->
    register_handler(RecordTypes, Module, ?DEFAULT_HANDLER_VERSION).

-doc "Register a record handler with version".
-spec register_handler([dns:type()], module(), integer()) -> ok.
register_handler(RecordTypes, Module, Version) ->
    gen_server:call(?MODULE, {register_handler, {Module, RecordTypes, Version}}, ?TIMEOUT).

-doc "Get all registered handlers along with the DNS types they handle and associated versions".
-spec get_versioned_handlers() -> [versioned_handler()].
get_versioned_handlers() ->
    persistent_term:get(?MODULE, []).

-doc "Filter records through registered handlers.".
-spec call_filters([dns:rr()]) -> [dns:rr()].
call_filters(Records) ->
    filter_records(Records, get_versioned_handlers()).

filter_records(Records, []) ->
    Records;
filter_records(Records, [{_, Filter, _, _, _, _} | Rest]) ->
    filter_records(Filter(Records), Rest).

-doc "Call all registered handlers.".
-spec call_handlers(dns:message(), dns:labels(), dns:type(), [dns:rr()]) -> [dns:rr()].
call_handlers(Message, QLabels, QType, Records) ->
    Handlers = get_versioned_handlers(),
    lists:flatmap(call_handlers_fun(Message, QLabels, QType, Records), Handlers).

-spec call_handlers_fun(dns:message(), dns:labels(), dns:type(), [dns:rr()]) ->
    fun((...) -> [dns:rr()]).
call_handlers_fun(Message, QLabels, ?DNS_TYPE_ANY, Records) ->
    fun
        ({Handler, _, _, _, _, ?MINIMUM_HANDLER_VERSION}) ->
            Handler(dns:labels_to_dname(QLabels), ?DNS_TYPE_ANY, Records, Message);
        ({Handler, _, _, _, _, ?DEFAULT_HANDLER_VERSION}) ->
            Handler(Message, QLabels, ?DNS_TYPE_ANY, Records)
    end;
call_handlers_fun(Message, QLabels, QType, Records) ->
    fun
        ({Handler, _, _, _, Types, ?MINIMUM_HANDLER_VERSION}) ->
            case lists:member(QType, Types) of
                true -> Handler(dns:labels_to_dname(QLabels), QType, Records, Message);
                false -> []
            end;
        ({Handler, _, _, _, Types, ?DEFAULT_HANDLER_VERSION}) ->
            case lists:member(QType, Types) of
                true -> Handler(Message, QLabels, QType, Records);
                false -> []
            end
    end.

-spec call_map_nsec_rr_types([dns:type()]) -> [dns:type()].
call_map_nsec_rr_types(Types) ->
    case get_versioned_handlers() of
        [] ->
            %% No handlers, return the types as is
            Types;
        Handlers ->
            %% Map the types using the handlers
            MappedTypes = lists:flatmap(
                fun(Type) ->
                    case lists:keyfind([Type], 5, Handlers) of
                        false -> [Type];
                        {_, _, _, M, _, _} -> M:nsec_rr_type_mapper(Type)
                    end
                end,
                Types
            ),
            lists:usort(MappedTypes)
    end.

-spec call_map_nsec_rr_types(dns:type(), [dns:type()]) -> [dns:type()].
call_map_nsec_rr_types(QType, Types) ->
    Handlers = get_versioned_handlers(),
    MappedTypes = map_nsec_rr_types(QType, Types, Handlers),
    lists:usort(MappedTypes).

-spec map_nsec_rr_types(dns:type(), [dns:type()], [versioned_handler()]) ->
    [dns:type()].
map_nsec_rr_types(_QType, Types, []) ->
    Types;
map_nsec_rr_types(QType, Types, Handlers) ->
    lists:flatmap(
        fun(Type) ->
            case lists:keyfind([Type], 5, Handlers) of
                false ->
                    [Type];
                {_, _, Mapper, _, _, _} ->
                    Mapper(Type, QType)
            end
        end,
        Types
    ).

-doc "Start the handler registry process".
-spec start_link() -> gen_server:start_ret().
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, noargs, [{hibernate_after, 0}]).

% gen_server callbacks
-doc false.
-spec init(noargs) -> {ok, state()}.
init(noargs) ->
    process_flag(trap_exit, true),
    Handlers = prepare_handlers(),
    persistent_term:put(?MODULE, Handlers),
    {ok, #handlers_state{}}.

-doc false.
-spec handle_call
    ({register_handler, {module(), [dns:type()], integer()}}, gen_server:from(), state()) ->
        {reply, ok, state()};
    (dynamic(), gen_server:from(), state()) ->
        {reply, not_implemented, state()}.
handle_call({register_handler, Handler}, _, State) ->
    NewHandlers = prepare_handlers([Handler], State#handlers_state.handlers),
    persistent_term:put(?MODULE, NewHandlers),
    {reply, ok, State#handlers_state{handlers = NewHandlers}};
handle_call(_, _, State) ->
    {reply, not_implemented, State}.

-doc false.
-spec handle_cast(term(), state()) -> {noreply, state()}.
handle_cast(_, State) ->
    {noreply, State}.

-doc false.
-spec terminate(term(), state()) -> term().
terminate(_, _) ->
    persistent_term:erase(?MODULE).

-spec prepare_handlers() -> [versioned_handler()].
prepare_handlers() ->
    Handlers = application:get_env(erldns, packet_handlers, []),
    prepare_handlers(Handlers, []).

-spec prepare_handlers([dynamic()], [versioned_handler()]) -> [versioned_handler()].
prepare_handlers([], Acc) ->
    lists:reverse(Acc);
prepare_handlers([{Module, RecordTypes, Version} | Rest], Acc) ->
    ?LOG_INFO(
        #{what => registered_handler, module => Module, types => RecordTypes, version => Version},
        #{domain => [erldns, pipeline]}
    ),
    maybe
        {module, Module} ?= code:ensure_loaded(Module),
        true ?= erlang:function_exported(Module, handle, 4),
        true ?= erlang:function_exported(Module, filter, 1),
        true ?= erlang:function_exported(Module, nsec_rr_type_mapper, 2),
        true ?= Version >= ?MINIMUM_HANDLER_VERSION orelse {error, {version, Version}},
        {ok, RecordTypesNums} ?= ensure_valid_record_types(RecordTypes, []),
        Prepared = {
            fun Module:handle/4,
            fun Module:filter/1,
            fun Module:nsec_rr_type_mapper/2,
            Module,
            RecordTypesNums,
            Version
        },
        prepare_handlers(Rest, [Prepared | Acc])
    else
        {error, Reason} ->
            erlang:error({badhandler, Module, Reason});
        false ->
            erlang:error({badhandler, Module, module_does_not_export_call})
    end.

ensure_valid_record_types([], Acc) ->
    {ok, lists:reverse(Acc)};
ensure_valid_record_types([Type | Rest], Acc) when is_integer(Type) ->
    ensure_valid_record_types(Rest, [Type | Acc]);
ensure_valid_record_types([TypeBin | Rest], Acc) when is_binary(TypeBin) ->
    case dns_names:name_type(TypeBin) of
        undefined ->
            {error, {record_type, TypeBin}};
        Type ->
            ensure_valid_record_types(Rest, [Type | Acc])
    end.
