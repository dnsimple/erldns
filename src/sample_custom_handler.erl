-module(sample_custom_handler).

-include("dns.hrl").

-behavior(gen_server).

-export([start_link/0, handle/1]).

% Gen server hooks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-record(state, {}).

%% API

start_link() ->
  gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

handle(Records) ->
  gen_server:call(?MODULE, {handle, Records}).

%% Gen server hooks
init([]) ->
  erldns_handler:register_handler([?DNS_TYPE_A], ?MODULE),
  erldns_zone_cache:register_parser([<<"SAMPLE">>], ?MODULE),
  {ok, #state{}}.

handle_call({handle, Records}, _From, State) ->
  lager:info("Received handle message for ~p", [Records]),
  {reply, [], State}.

handle_cast(_Message, State) ->
  {noreply, State}.

handle_info(_Message, State) ->
  {noreply, State}.

terminate(_Reason, _State) ->
  ok.

code_change(_PreviousVersion, State, _Extra) ->
  {ok, State}.
