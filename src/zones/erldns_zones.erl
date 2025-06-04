-module(erldns_zones).

-behaviour(supervisor).

-export([start_link/0, init/1]).

-doc false.
-spec start_link() -> supervisor:startlink_ret().
start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, noargs).

-doc false.
-spec init(noargs) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init(noargs) ->
    SupFlags = #{strategy => rest_for_one, intensity => 1, period => 5},
    Children =
        [
            worker(erldns_zone_cache),
            worker(erldns_zone_parser),
            worker(erldns_zone_encoder),
            worker(erldns_zone_loader)
        ],
    {ok, {SupFlags, Children}}.

worker(Module) ->
    #{id => Module, start => {Module, start_link, []}, type => worker}.
