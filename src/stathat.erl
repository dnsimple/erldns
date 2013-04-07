%%
%% @author Patrick Crosby <patrick@stathat.com>
%% @author Sam Elliott <sam@lenary.co.uk>
%% @version 0.2
%% @doc Gen Server for sending data to stathat.com stat tracking service.
%%
%% <h4>Example:</h4>
%% <pre><code>
%% 1&gt; {ok, Pid} = stathat:start().
%% 2&gt; stathat:ez_count("erlang@stathat.com", "messages sent", 1).
%% ok.
%% 3&gt; stathat:ez_value("erlang@stathat.com", "request time", 92.194).
%% ok.
%%

-module(stathat).

-author("Patrick Crosby <patrick@stathat.com>").
-author("Sam Elliott <sam@lenary.co.uk").
-version("0.2").

-behaviour(gen_server).

-export([
                start/0,
                start_link/0,
                child_definition/0,
                ez_count/3,
                ez_value/3,
                cl_count/3,
                cl_value/3
        ]).

-export([
                init/1, 
                handle_call/3, 
                handle_cast/2, 
                handle_info/2, 
                terminate/2, 
                code_change/3
        ]).


-define(SH_BASE_URL(X), "http://www.stathat.com/" ++ X).

%% Public API

start() ->
    gen_server:start({local, ?MODULE}, ?MODULE, [], []).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

% Use this to get a child definition for a supervisor
child_definition() ->
    {?MODULE, {stathat, start_link, []}, permanent, infinity, worker, [?MODULE]}.

ez_count(Ezkey, Stat, Count) ->
    gen_server:cast(?MODULE, {ez_count, Ezkey, Stat, Count}).

ez_value(Ezkey, Stat, Value) ->
    gen_server:cast(?MODULE, {ez_value, Ezkey, Stat, Value}).

cl_count(UserKey, StatKey, Count) ->
    gen_server:cast(?MODULE, {cl_count, UserKey, StatKey, Count}).

cl_value(UserKey, StatKey, Value) ->
    gen_server:cast(?MODULE, {cl_value, UserKey, StatKey, Value}).


% gen_server callbacks

init(_Args) ->
    case inets:start() of
        ok -> {ok, {}};
        {error, already_started} -> {ok, {}};
        {error, Err} -> {stop, {error_starting_inets, Err}}
    end.

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.


handle_cast({ez_count, Ezkey, Stat, Count}, State) ->
    Url = build_url("ez", [{"ezkey", Ezkey}, {"stat", Stat}, {"count", ntoa(Count)}]),
    httpc:request(get, {?SH_BASE_URL(Url), []}, [], [{sync, false}]),
    {noreply, State};

handle_cast({ez_value, Ezkey, Stat, Value}, State) ->
    Url = build_url("ez", [{"ezkey", Ezkey}, {"stat", Stat}, {"value", ntoa(Value)}]),
    httpc:request(get, {?SH_BASE_URL(Url), []}, [], [{sync, false}]),
    {noreply, State};

handle_cast({cl_count, UserKey, StatKey, Count}, State) ->
    Url = build_url("c", [{"ukey", UserKey}, {"key", StatKey}, {"count", ntoa(Count)}]),
    httpc:request(get, {?SH_BASE_URL(Url), []}, [], [{sync, false}]),
    {noreply, State};

handle_cast({cl_value, UserKey, StatKey, Value}, State) ->
    Url = build_url("v", [{"ukey", UserKey}, {"key", StatKey}, {"value", ntoa(Value)}]),
    httpc:request(get, {?SH_BASE_URL(Url), []}, [], [{sync, false}]),
    {noreply, State};

handle_cast(_Request, State) ->
    {noreply, State}.

handle_info({_RequestId, {error, _Reason}}, State) ->
    % You could do something here, but I won't
    {noreply, State};
handle_info({_RequestId, _Result}, State) ->
    % Again, you might do something here but I won't
    {noreply, State};
handle_info(_Request, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

% private methods

ntoa(Num) when is_list(Num) ->
        Num;
ntoa(Num) when is_float(Num) ->
        lists:flatten(io_lib:format("~f", [Num]));
ntoa(Num) when is_integer(Num) ->
        integer_to_list(Num).

% url utility functions (borrowed from twitter_client module)

build_url(Url, []) -> Url;
build_url(Url, Args) ->
        Url ++ "?" ++ lists:concat(
                lists:foldl(
                        fun (Rec, []) -> [Rec]; (Rec, Ac) -> [Rec, "&" | Ac] end, [],
                                [K ++ "=" ++ url_encode(V) || {K, V} <- Args]
                )
        ).

url_encode([H|T]) ->
        if
                H >= $a, $z >= H ->
                        [H|url_encode(T)];
                H >= $A, $Z >= H ->
                        [H|url_encode(T)];
                H >= $0, $9 >= H ->
                        [H|url_encode(T)];
                H == $_; H == $.; H == $-; H == $/; H == $: -> % FIXME: more..
        [H|url_encode(T)];
true ->
        case integer_to_hex(H) of
                [X, Y] ->
                        [$%, X, Y | url_encode(T)];
                [X] ->
                        [$%, $0, X | url_encode(T)]
        end
end;

url_encode([]) -> [].

integer_to_hex(I) ->
        case catch erlang:integer_to_list(I, 16) of
                {'EXIT', _} ->
                        old_integer_to_hex(I);
                Int ->
                        Int
        end.

old_integer_to_hex(I) when I<10 ->
        integer_to_list(I);
old_integer_to_hex(I) when I<16 ->
        [I-10+$A];
old_integer_to_hex(I) when I>=16 ->
        N = trunc(I/16),
        old_integer_to_hex(N) ++ old_integer_to_hex(I rem 16).

