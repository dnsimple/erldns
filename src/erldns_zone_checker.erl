-module(erldns_zone_checker).

-behavior(gen_server).

% API
-export([start_link/0, check/0, check_zones/1]).

% Gen server hooks
-export([init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3
  ]).

-define(SERVER, ?MODULE).
-define(CHECK_INTERVAL, 1000 * 600). % Every N seconds

-record(state, {tref}).

start_link() ->
  gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

check() ->
  check_zones(erldns_zone_cache:zone_names_and_versions()).

check_zones(NamesAndVersions) ->
  gen_server:cast(?SERVER, {check_zones, NamesAndVersions}).

init([]) ->
  {ok, Tref} = timer:apply_interval(?CHECK_INTERVAL, ?MODULE, check, []),
  {ok, #state{tref = Tref}}.

handle_call(_Message, _From, State) ->
  {reply, ok, State}.

handle_cast({check_zones, NamesAndVersions}, State) ->
  lists:map(fun({Name, Version}) -> send_zone_check(Name, Version) end, NamesAndVersions),
  {noreply, State}.

handle_info(_Message, State) ->
  {noreply, State}.

terminate(_Reason, _State) ->
  ok.

code_change(_PreviousVersion, State, _Extra) ->
  {ok, State}.

%% Private API
send_zone_check(Name, Sha) ->
  %lager:debug("Sending zone check for ~p (~p)", [Name, Sha]),
  erldns_zone_client:check_zone(Name, Sha),
  ok.
