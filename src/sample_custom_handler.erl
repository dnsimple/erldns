-module(sample_custom_handler).

-include("dns.hrl").
-include("erldns.hrl").

-behavior(gen_server).

-export([start_link/0, handle/1, parse/1]).

% Gen server hooks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-define(DNS_SAMPLE_TYPE, 20001).

-record(state, {}).

%% API

start_link() ->
  gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

handle(Records) ->
  gen_server:call(?MODULE, {handle, Records}).

parse(Record) ->
  gen_server:call(?MODULE, {parse, Record}).

%% Gen server hooks
init([]) ->
  erldns_handler:register_handler([?DNS_TYPE_A], ?MODULE),
  erldns_zone_cache:register_parser([<<"SAMPLE">>], ?MODULE),
  {ok, #state{}}.

handle_call({handle, Records}, _From, State) ->
  lager:info("Received handle message for ~p", [Records]),
  {reply, [], State};

handle_call({parse, Record}, _From, State) ->
  lager:info("Received parse message for ~p", [Record]),
  DnsRecord = #dns_rr{
    name = Record#db_rr.name,
    type = ?DNS_SAMPLE_TYPE,
    data = Record#db_rr.content,
    ttl  = erldns_records:default_ttl(Record#db_rr.ttl)
  },
  lager:info("Created record: ~p", [DnsRecord]),
  {reply, [DnsRecord], State}.

handle_cast(_Message, State) ->
  {noreply, State}.

handle_info(_Message, State) ->
  {noreply, State}.

terminate(_Reason, _State) ->
  ok.

code_change(_PreviousVersion, State, _Extra) ->
  {ok, State}.
