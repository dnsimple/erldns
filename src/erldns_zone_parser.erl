-module(erldns_zone_parser).

-behavior(gen_server).

-include("dns.hrl").
-include("erldns.hrl").

-export([start_link/0, zones_to_erlang/1, zone_to_erlang/1, register_parsers/1, register_parser/1]).

% Gen server hooks
-export([init/1,
	 handle_call/3,
	 handle_cast/2,
	 handle_info/2,
	 terminate/2,
	 code_change/3
       ]).

-define(SERVER, ?MODULE).

-record(state, {parsers}).

%% Public API

start_link() ->
  gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

zones_to_erlang(Zones) ->
  gen_server:call(?SERVER, {parse_zones, Zones}).

%% Takes a JSON zone and turns it into the tuple {Name, Records}.
zone_to_erlang(Zone) ->
  gen_server:call(?SERVER, {parse_zone, Zone}).

register_parsers(Modules) ->
  lager:info("Registering custom parsers: ~p", [Modules]),
  gen_server:call(?SERVER, {register_parsers, Modules}).

register_parser(Module) ->
  lager:info("Registering custom parser: ~p", [Module]),
  gen_server:call(?SERVER, {register_parser, Module}).

%% Gen server hooks
init([]) ->
  {ok, #state{parsers = []}}.

handle_call({parse_zones, Zones}, _From, State) ->
  {reply, zones_to_erlang(Zones, State#state.parsers, []), State};

handle_call({parse_zone, Zone}, _From, State) ->
  {reply, json_to_erlang(Zone, State#state.parsers), State};

handle_call({register_parsers, Modules}, _From, State) ->
  {reply, ok, State#state{parsers = State#state.parsers ++ Modules}};

handle_call({register_parser, Module}, _From, State) ->
  {reply, ok, State#state{parsers = State#state.parsers ++ [Module]}}.

handle_cast(_, State) ->
  {noreply, State}.

handle_info(_, State) ->
  {noreply, State}.

terminate(_, _State) ->
  ok.

code_change(_, State, _) ->
  {ok, State}.



% Internal API
zones_to_erlang([], _Parsers, Zones) -> Zones;

zones_to_erlang([Zone|Rest], Parsers, Zones) ->
  ParsedZone = json_to_erlang(Zone, Parsers),
  zones_to_erlang(Rest, Parsers, Zones ++ [ParsedZone]).

json_to_erlang([{<<"name">>, Name}, {<<"records">>, JsonRecords}], Parsers) ->
  Records = lists:map(
    fun(JsonRecord) ->
        case json_record_to_erlang(JsonRecord) of
          {} ->
            try_custom_parsers(JsonRecord, Parsers);
          ParsedRecord -> ParsedRecord
        end
    end, JsonRecords),
  FilteredRecords = lists:filter(
    fun(R) ->
        case R of
          {} -> false;
          _ -> true
        end
    end, Records),
  {Name, FilteredRecords}.

try_custom_parsers(_JsonRecord, []) -> {};
try_custom_parsers(JsonRecord, [Parser|Rest]) ->
  case Parser:json_record_to_erlang(JsonRecord) of
    {} -> try_custom_parsers(JsonRecord, Rest);
    Record -> Record
  end.

% Internal converters
json_record_to_erlang([{<<"name">>, Name}, {<<"type">>, <<"SOA">>}, {<<"data">>, [{<<"mname">>, Mname}, {<<"rname">>, Rname}, {<<"serial">>, Serial}, {<<"refresh">>, Refresh}, {<<"retry">>, Retry}, {<<"expire">>, Expire},{<<"minimum">>, Minimum}]}, {<<"ttl">>, Ttl}]) ->
  #dns_rr{name = Name, type = ?DNS_TYPE_SOA, data = #dns_rrdata_soa{mname = Mname, rname = Rname, serial = Serial, refresh = Refresh, retry = Retry, expire = Expire, minimum = Minimum}, ttl = Ttl};

json_record_to_erlang([{<<"name">>, Name}, {<<"type">>, <<"NS">>}, {<<"data">>, [{<<"dname">>, Dname}]}, {<<"ttl">>, Ttl}]) ->
  #dns_rr{name = Name, type = ?DNS_TYPE_NS, data = #dns_rrdata_ns{dname = Dname}, ttl = Ttl};

json_record_to_erlang([{<<"name">>, Name}, {<<"type">>, <<"A">>}, {<<"data">>, [{<<"ip">>, Ip}]}, {<<"ttl">>, Ttl}]) ->
  case inet_parse:address(binary_to_list(Ip)) of
    {ok, Address} ->
      #dns_rr{name = Name, type = ?DNS_TYPE_A, data = #dns_rrdata_a{ip = Address}, ttl = Ttl};
    {error, Reason} ->
      lager:error("Failed to parse A record address ~p: ~p", [Ip, Reason]),
      {}
  end;

json_record_to_erlang([{<<"name">>, Name}, {<<"type">>, <<"AAAA">>}, {<<"data">>, [{<<"ip">>, Ip}]}, {<<"ttl">>, Ttl}]) ->
  case inet_parse:address(binary_to_list(Ip)) of
    {ok, Address} ->
      #dns_rr{name = Name, type = ?DNS_TYPE_AAAA, data = #dns_rrdata_aaaa{ip = Address}, ttl = Ttl};
    {error, Reason} ->
      lager:error("Failed to parse AAAA record address ~p: ~p", [Ip, Reason]),
      {}
  end;

json_record_to_erlang([{<<"name">>, Name}, {<<"type">>, <<"CNAME">>}, {<<"data">>, [{<<"dname">>, Dname}]}, {<<"ttl">>, Ttl}]) ->
  #dns_rr{name = Name, type = ?DNS_TYPE_CNAME, data = #dns_rrdata_cname{dname = Dname}, ttl = Ttl};

json_record_to_erlang([{<<"name">>, Name}, {<<"type">>, <<"MX">>}, {<<"data">>, [{<<"preference">>, Preference}, {<<"exchange">>, Exchange}]}, {<<"ttl">>, Ttl}]) ->
  #dns_rr{name = Name, type = ?DNS_TYPE_MX, data = #dns_rrdata_mx{exchange = Exchange, preference = Preference}, ttl = Ttl};

json_record_to_erlang([{<<"name">>, Name}, {<<"type">>, <<"TXT">>}, {<<"data">>, [{<<"txt">>, Text}]}, {<<"ttl">>, Ttl}]) ->
  #dns_rr{name = Name, type = ?DNS_TYPE_TXT, data = #dns_rrdata_txt{txt = [Text]}, ttl = Ttl};

json_record_to_erlang([{<<"name">>, Name}, {<<"type">>, <<"SPF">>}, {<<"data">>, [{<<"spf">>, Spf}]}, {<<"ttl">>, Ttl}]) ->
  #dns_rr{name = Name, type = ?DNS_TYPE_SPF, data = #dns_rrdata_spf{spf = [Spf]}, ttl = Ttl};

json_record_to_erlang([{<<"name">>,Name},{<<"type">>,<<"PTR">>},{<<"data">>,[{<<"dname">>, Dname}]},{<<"ttl">>, Ttl}]) ->
  #dns_rr{name = Name, type = ?DNS_TYPE_PTR, data = #dns_rrdata_ptr{dname = Dname}, ttl = Ttl};

json_record_to_erlang([{<<"name">>,Name},{<<"type">>,<<"SSHFP">>},{<<"data">>,[{<<"alg">>,Alg},{<<"fptype">>,Fptype},{<<"fp">>,Fp}]},{<<"ttl">>,Ttl}]) ->
  #dns_rr{name = Name, type = ?DNS_TYPE_SSHFP, data = #dns_rrdata_sshfp{alg = Alg, fp_type = Fptype, fp = Fp}, ttl = Ttl};

json_record_to_erlang([{<<"name">>, Name}, {<<"type">>, <<"SRV">>}, {<<"data">>, [{<<"priority">>, Priority}, {<<"weight">>, Weight}, {<<"port">>, Port}, {<<"target">>, Target}]}, {<<"ttl">>, Ttl}]) ->
  #dns_rr{name = Name, type = ?DNS_TYPE_SRV, data = #dns_rrdata_srv{priority = Priority, weight = Weight, port = Port, target = Target}, ttl = Ttl};

json_record_to_erlang([{<<"name">>, Name}, {<<"type">>, <<"NAPTR">>}, {<<"data">>, [{<<"order">>, Order}, {<<"preference">>, Preference}, {<<"flags">>, Flags}, {<<"services">>, Services}, {<<"regexp">>, Regexp}, {<<"replacement">>, Replacement}]}, {<<"ttl">>, Ttl}]) ->
  #dns_rr{name = Name, type = ?DNS_TYPE_NAPTR, data = #dns_rrdata_naptr{order = Order, preference = Preference, flags = Flags, services = Services, regexp = Regexp, replacement = Replacement}, ttl = Ttl};

json_record_to_erlang(_JsonRecord) -> {}.

