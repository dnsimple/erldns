-module(erldns_app).
-moduledoc false.

-include_lib("kernel/include/logger.hrl").

-behaviour(application).

-export([start/2, stop/1]).

-spec start(application:start_type(), term()) -> {ok, pid()} | {error, term()}.
start(_Type, _Args) ->
    ?LOG_INFO(#{what => starting_erldns_application}),
    case erldns_sup:start_link() of
        {ok, Pid} when is_pid(Pid) ->
            erldns_admin:maybe_start(),
            {ok, Pid};
        {error, Reason} ->
            ?LOG_ERROR(#{what => erldns_start_failed, reason => Reason}),
            {error, Reason}
    end.

-spec stop(term()) -> term().
stop(_State) ->
    ?LOG_INFO(#{what => stop_erldns_application}).
