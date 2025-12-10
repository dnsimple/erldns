-module(erldns_zone_loader_getter).
-moduledoc false.

-behaviour(gen_server).

-include_lib("kernel/include/logger.hrl").

-define(WILDCARD_JSON, "**/*.json").
-define(WILDCARD_ZONE, "**/*.zone").
-define(WILDCARD_AUTO, "**/*.{json,zone}").
-define(LOG_METADATA, #{domain => [erldns, zones, load]}).

-export([respond/3]).
-export([load_zones/1]).
-export([start_link/1, init/1, handle_call/3, handle_cast/2]).

-record(file_getter, {
    running_call :: tag(),
    pending_requests = #{} :: #{gen_server:request_id() => {file:filename(), boolean()}},
    pending_calls = queue:new() :: queue:queue({gen_server:from(), erldns_zones:config()}),
    zones_loaded = 0 :: non_neg_integer(),
    strict = false :: boolean(),
    error :: undefined | term()
}).
-type state() :: #file_getter{}.
-type tag() :: undefined | gen_server:from().
-export_type([tag/0]).

-spec load_zones(erldns_zones:config()) -> non_neg_integer() | {error, term()}.
load_zones(Config) ->
    gen_server:call(?MODULE, {load_zones, Config}, infinity).

-spec start_link(erldns_zones:config()) -> gen_server:startlink_ret().
start_link(Config) ->
    Timeout = maps:get(timeout, Config, infinity),
    StartOpts = [{hibernate_after, Timeout}, {timeout, Timeout}],
    gen_server:start_link({local, ?MODULE}, ?MODULE, Config, StartOpts).

-spec do_load_zones(state(), tag(), erldns_zones:config()) -> state().
do_load_zones(State, From, #{
    path := ConfigPath, format := Format, strict := Strict, timeout := Timeout
}) ->
    case find_zone_files(ConfigPath, Format) of
        [] ->
            maybe_reply(From, 0),
            maybe_process_next_request(State);
        Files ->
            State1 = initialize_state(State, From, Strict, Files),
            State2 = round_robin_files(State1, From, Strict, Files),
            get_responses(State2, Timeout)
    end;
do_load_zones(State, From, _) ->
    maybe_reply(From, 0),
    maybe_process_next_request(State).

-spec round_robin_files(state(), tag(), boolean(), [file:filename()]) ->
    state().
round_robin_files(State, _, _, []) ->
    State;
round_robin_files(State, Tag, Strict, [File | Rest]) ->
    {ok, Pid} = erldns_zone_loader_worker:load_file(Tag, File, Strict),
    NewPendingRequests = maps:put(Pid, {File, Strict}, State#file_getter.pending_requests),
    NewState = State#file_getter{pending_requests = NewPendingRequests},
    round_robin_files(NewState, Tag, Strict, Rest).

get_responses(#file_getter{pending_requests = P} = State, _) when 0 =:= map_size(P) ->
    State;
get_responses(#file_getter{running_call = Tag} = State, Timeout) ->
    receive
        {Tag, From, Reply} ->
            NewState = handle_request_reply(From, Reply, State),
            get_responses(NewState, Timeout)
    after Timeout ->
        erlang:error(timeout)
    end.

-spec respond(tag(), pid(), term()) -> dynamic().
respond(Tag, From, Reply) ->
    whereis(?MODULE) ! {Tag, From, Reply}.

maybe_reply(undefined, _) ->
    ok;
maybe_reply(From, Reply) ->
    gen_server:reply(From, Reply).

initialize_state(State0, From, Strict, Files) ->
    ?LOG_INFO(
        #{
            what => starting_parallel_zone_load,
            file_count => length(Files),
            strict => Strict
        },
        ?LOG_METADATA
    ),
    State0#file_getter{
        strict = Strict,
        running_call = From,
        pending_requests = #{},
        error = undefined
    }.

-spec find_zone_files(file:name(), erldns_zones:format()) -> [file:filename()].
find_zone_files(Path, Format) ->
    case {filelib:is_dir(Path), Format} of
        {false, _} ->
            [Path];
        {true, json} ->
            filelib:wildcard(filename:join([Path, ?WILDCARD_JSON]), prim_file);
        {true, zonefile} ->
            filelib:wildcard(filename:join([Path, ?WILDCARD_ZONE]), prim_file);
        {true, auto} ->
            filelib:wildcard(filename:join([Path, ?WILDCARD_AUTO]), prim_file)
    end.

handle_request_reply(From, {ok, ZCount}, #file_getter{running_call = RunningCall} = State) ->
    #file_getter{pending_requests = PendingRequests, zones_loaded = ZonesLoaded} = State,
    NewPendingRequests = maps:remove(From, PendingRequests),
    NewZonesLoaded = ZonesLoaded + ZCount,
    % Check if all requests are complete
    case maps:size(NewPendingRequests) =:= 0 of
        true ->
            maybe_reply(RunningCall, NewZonesLoaded),
            ?LOG_INFO(
                #{what => parallel_zone_load_completed, zones_loaded => NewZonesLoaded},
                ?LOG_METADATA
            ),
            NewState = maybe_process_next_request(State#file_getter{
                running_call = undefined,
                pending_requests = #{},
                zones_loaded = 0,
                error = undefined
            }),
            NewState;
        false ->
            NewState = State#file_getter{
                pending_requests = NewPendingRequests,
                zones_loaded = NewZonesLoaded
            },
            NewState
    end;
handle_request_reply(From, {error, Error}, #file_getter{running_call = RunningCall} = State) ->
    #file_getter{pending_requests = PendingRequests, strict = Strict, error = CurrentError} = State,
    NewPendingRequests = maps:remove(From, PendingRequests),
    % Track the first error
    NewError =
        case CurrentError of
            undefined -> Error;
            _ -> CurrentError
        end,
    % Check if all requests are complete
    case maps:size(NewPendingRequests) =:= 0 of
        true ->
            % All files processed
            case Strict andalso NewError =/= undefined of
                true ->
                    % Strict mode and error occurred - reply with error
                    maybe_reply(RunningCall, {error, NewError}),
                    ?LOG_ERROR(
                        #{what => parallel_zone_load_failed, error => NewError},
                        ?LOG_METADATA
                    );
                false ->
                    % Non-strict or no error - reply with count
                    maybe_reply(RunningCall, State#file_getter.zones_loaded),
                    ?LOG_INFO(
                        #{
                            what => parallel_zone_load_completed,
                            zones_loaded => State#file_getter.zones_loaded
                        },
                        ?LOG_METADATA
                    )
            end,
            % Process next queued request if any
            maybe_process_next_request(State#file_getter{
                running_call = undefined,
                pending_requests = #{},
                zones_loaded = 0,
                error = undefined
            });
        false ->
            % Still waiting for more replies
            State#file_getter{
                pending_requests = NewPendingRequests,
                error = NewError
            }
    end.

-spec maybe_process_next_request(state()) -> state().
maybe_process_next_request(#file_getter{pending_calls = Queue} = State) ->
    case queue:out(Queue) of
        {{value, {From, Config}}, NewQueue} ->
            NewState = State#file_getter{running_call = undefined, pending_calls = NewQueue},
            do_load_zones(NewState, From, Config);
        {empty, NewQueue} ->
            State#file_getter{running_call = undefined, pending_calls = NewQueue}
    end.

-spec init(erldns_zones:config()) -> {ok, state()}.
init(Config) ->
    State = do_load_zones(#file_getter{}, undefined, Config),
    {ok, State}.

-spec handle_call
    ({load_zones, erldns_zones:config()}, gen_server:from(), state()) ->
        {noreply, state()};
    (dynamic(), gen_server:from(), state()) ->
        {reply, term(), state()}.
handle_call({load_zones, Config}, From, #file_getter{running_call = undefined} = State) ->
    NewState = do_load_zones(State, From, Config),
    {noreply, NewState};
handle_call({load_zones, Config}, From, State) ->
    NewQueue = queue:in({From, Config}, State#file_getter.pending_calls),
    ?LOG_INFO(#{what => request_queued, queue_length => queue:len(NewQueue)}, ?LOG_METADATA),
    {noreply, State#file_getter{pending_calls = NewQueue}};
handle_call(Request, From, State) ->
    ?LOG_INFO(#{what => unexpected_call, from => From, request => Request}, ?LOG_METADATA),
    {reply, {error, not_implemented}, State}.

-spec handle_cast(term(), state()) -> {noreply, state()} | {noreply, state(), hibernate}.
handle_cast(Msg, State) ->
    ?LOG_INFO(#{what => unexpected_cast, msg => Msg}, ?LOG_METADATA),
    {noreply, State, hibernate}.
