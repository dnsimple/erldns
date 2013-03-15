-module(erldns_zone_parser).

-behavior(gen_server).

-include("dns.hrl").
-include("erldns.hrl").

-export([start_link/0, zone_to_erlang/1, register_parsers/1, register_parser/1]).

% Gen server hooks
-export([init/1,
	 handle_call/3,
	 handle_cast/2,
	 handle_info/2,
	 terminate/2,
	 code_change/3
       ]).

-define(SERVER, ?MODULE).
-define(MAX_TXT_SIZE, 255).

-record(state, {parsers}).

%% Public API

start_link() ->
  gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

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
json_to_erlang([{<<"name">>, Name}, {<<"records">>, JsonRecords}], Parsers) ->
  lager:debug("Parsing zone ~p with ~p records", [Name, length(JsonRecords)]),
  Records = lists:map(
    fun(JsonRecord) ->
        Data = json_record_to_list(JsonRecord),
        case json_record_to_erlang(Data) of
          {} -> try_custom_parsers(Data, Parsers);
          ParsedRecord ->
            lager:debug("Parsed record: ~p", [ParsedRecord]),
            ParsedRecord
        end
    end, JsonRecords),
  FilteredRecords = lists:filter(
    fun(R) ->
        case R of
          {} -> false;
          _ -> true
        end
    end, Records),
  DistinctRecords = lists:usort(FilteredRecords),
  lager:debug("Parsed ~p records for ~p", [length(DistinctRecords), Name]),
  {Name, DistinctRecords}.

json_record_to_list(JsonRecord) ->
  [
    proplists:get_value(<<"name">>, JsonRecord),
    proplists:get_value(<<"type">>, JsonRecord),
    proplists:get_value(<<"ttl">>, JsonRecord),
    proplists:get_value(<<"data">>, JsonRecord)
  ].

try_custom_parsers([Name, Type, Ttl, Rdata] = Data, []) ->
  lager:debug("~p could not parse ~p ~p ~p ~p", [?MODULE, Name, Type, Ttl, Rdata]),
  {};
try_custom_parsers(Data, [Parser|Rest]) ->
  case Parser:json_record_to_erlang(Data) of
    {} -> try_custom_parsers(Data, Rest);
    Record -> Record
  end.

% Internal converters
json_record_to_erlang([Name, Type, _Ttl, null]) ->
  lager:error("record name=~p type=~p has null data", [Name, Type]),
  {};

json_record_to_erlang([Name, <<"SOA">>, Ttl, Data]) ->
  #dns_rr{
    name = Name,
    type = ?DNS_TYPE_SOA,
    data = #dns_rrdata_soa{
      mname = proplists:get_value(<<"mname">>, Data),
      rname = proplists:get_value(<<"rname">>, Data),
      serial = proplists:get_value(<<"serial">>, Data),
      refresh = proplists:get_value(<<"refresh">>, Data),
      retry = proplists:get_value(<<"retry">>, Data),
      expire = proplists:get_value(<<"expire">>, Data),
      minimum = proplists:get_value(<<"minimum">>, Data)
    },
    ttl = Ttl};

json_record_to_erlang([Name, <<"NS">>, Ttl, Data]) ->
  #dns_rr{
    name = Name,
    type = ?DNS_TYPE_NS,
    data = #dns_rrdata_ns{
      dname = proplists:get_value(<<"dname">>, Data)
    },
    ttl = Ttl};

json_record_to_erlang([Name, <<"A">>, Ttl, Data]) ->
  Ip = proplists:get_value(<<"ip">>, Data),
  case inet_parse:address(binary_to_list(Ip)) of
    {ok, Address} ->
      #dns_rr{name = Name, type = ?DNS_TYPE_A, data = #dns_rrdata_a{ip = Address}, ttl = Ttl};
    {error, Reason} ->
      lager:error("Failed to parse A record address ~p: ~p", [Ip, Reason]),
      {}
  end;

json_record_to_erlang([Name, <<"AAAA">>, Ttl, Data]) ->
  Ip = proplists:get_value(<<"ip">>, Data),
  case inet_parse:address(binary_to_list(Ip)) of
    {ok, Address} ->
      #dns_rr{name = Name, type = ?DNS_TYPE_AAAA, data = #dns_rrdata_aaaa{ip = Address}, ttl = Ttl};
    {error, Reason} ->
      lager:error("Failed to parse AAAA record address ~p: ~p", [Ip, Reason]),
      {}
  end;

json_record_to_erlang([Name, <<"CNAME">>, Ttl, Data]) ->
  #dns_rr{
    name = Name,
    type = ?DNS_TYPE_CNAME,
    data = #dns_rrdata_cname{dname = proplists:get_value(<<"dname">>, Data)},
    ttl = Ttl};

json_record_to_erlang([Name, <<"MX">>, Ttl, Data]) ->
  #dns_rr{
    name = Name,
    type = ?DNS_TYPE_MX,
    data = #dns_rrdata_mx{
      exchange = proplists:get_value(<<"exchange">>, Data),
      preference = proplists:get_value(<<"preference">>, Data)
    },
    ttl = Ttl};

json_record_to_erlang([Name, <<"HINFO">>, Ttl, Data]) ->
  #dns_rr{
    name = Name,
    type = ?DNS_TYPE_HINFO,
    data = #dns_rrdata_hinfo{
      cpu = proplists:get_value(<<"cpu">>, Data),
      os = proplists:get_value(<<"os">>, Data)
    },
    ttl = Ttl};

json_record_to_erlang([Name, <<"RP">>, Ttl, Data]) ->
  #dns_rr{
    name = Name,
    type = ?DNS_TYPE_RP,
    data = #dns_rrdata_rp{
      mbox = proplists:get_value(<<"mbox">>, Data),
      txt = proplists:get_value(<<"txt">>, Data)
    },
    ttl = Ttl};

json_record_to_erlang([Name, <<"TXT">>, Ttl, Data]) ->
  #dns_rr{
    name = Name,
    type = ?DNS_TYPE_TXT,
    data = #dns_rrdata_txt{txt = lists:flatten(parse_txt(proplists:get_value(<<"txt">>, Data)))},
    ttl = Ttl};

json_record_to_erlang([Name, <<"SPF">>, Ttl, Data]) ->
  #dns_rr{
    name = Name,
    type = ?DNS_TYPE_SPF,
    data = #dns_rrdata_spf{spf = [proplists:get_value(<<"spf">>, Data)]},
    ttl = Ttl};

json_record_to_erlang([Name, <<"PTR">>, Ttl, Data]) ->
  #dns_rr{
    name = Name,
    type = ?DNS_TYPE_PTR,
    data = #dns_rrdata_ptr{dname = proplists:get_value(<<"dname">>, Data)},
    ttl = Ttl};

json_record_to_erlang([Name, <<"SSHFP">>, Ttl, Data]) ->
  #dns_rr{
    name = Name,
    type = ?DNS_TYPE_SSHFP,
    data = #dns_rrdata_sshfp{
      alg = proplists:get_value(<<"alg">>, Data),
      fp_type = proplists:get_value(<<"fptype">>, Data),
      fp = proplists:get_value(<<"fp">>, Data)
    },
    ttl = Ttl};

json_record_to_erlang([Name, <<"SRV">>, Ttl, Data]) ->
  #dns_rr{
    name = Name,
    type = ?DNS_TYPE_SRV,
    data = #dns_rrdata_srv{
      priority = proplists:get_value(<<"priority">>, Data),
      weight = proplists:get_value(<<"weight">>, Data),
      port = proplists:get_value(<<"port">>, Data),
      target = proplists:get_value(<<"target">>, Data)
    },
    ttl = Ttl};

json_record_to_erlang([Name, <<"NAPTR">>, Ttl, Data]) ->
  #dns_rr{
    name = Name,
    type = ?DNS_TYPE_NAPTR,
    data = #dns_rrdata_naptr{
      order = proplists:get_value(<<"order">>, Data),
      preference = proplists:get_value(<<"preference">>, Data),
      flags = proplists:get_value(<<"flags">>, Data),
      services = proplists:get_value(<<"services">>, Data),
      regexp = proplists:get_value(<<"regexp">>, Data),
      replacement = proplists:get_value(<<"replacement">>, Data)
    },
    ttl = Ttl};

json_record_to_erlang([Name, Type, Ttl, Data]) ->
  {}.


parse_txt(Binary) when is_binary(Binary) -> parse_txt(binary_to_list(Binary));
parse_txt([C|Rest]) -> parse_txt_char([C|Rest], C, Rest, [], false).
parse_txt(String, [], [], _) -> [split_txt(String)];
parse_txt(_, [], Tokens, _) -> Tokens;
parse_txt(String, [C|Rest], Tokens, Escaped) -> parse_txt_char(String, C, Rest, Tokens, Escaped).
parse_txt(String, [C|Rest], Tokens, CurrentToken, Escaped) -> parse_txt_char(String, C, Rest, Tokens, CurrentToken, Escaped).
parse_txt_char(String, $", Rest, Tokens, _) -> parse_txt(String, Rest, Tokens, [], false);
parse_txt_char(String, _, Rest, Tokens, _) -> parse_txt(String, Rest, Tokens, false).
parse_txt_char(String, $", Rest, Tokens, CurrentToken, false) -> parse_txt(String, Rest, Tokens ++ [split_txt(CurrentToken)], false);
parse_txt_char(String, $", Rest, Tokens, CurrentToken, true) -> parse_txt(String, Rest, Tokens, CurrentToken ++ [$"], false);
parse_txt_char(String, $\\, Rest, Tokens, CurrentToken, false) -> parse_txt(String, Rest, Tokens, CurrentToken, true);
parse_txt_char(String, $\\, Rest, Tokens, CurrentToken, true) -> parse_txt(String, Rest, Tokens, CurrentToken ++ [$\\], false);
parse_txt_char(String, C, Rest, Tokens, CurrentToken, _) -> parse_txt(String, Rest, Tokens, CurrentToken ++ [C], false).

split_txt(Data) -> split_txt(Data, []).
split_txt(Data, Parts) ->
  case byte_size(list_to_binary(Data)) > ?MAX_TXT_SIZE of
    true ->
      First = list_to_binary(string:substr(Data, 1, ?MAX_TXT_SIZE)),
      Rest = string:substr(Data, ?MAX_TXT_SIZE + 1),
      case Rest of
        [] -> Parts ++ [First];
        _ -> split_txt(Rest, Parts ++ [First])
      end;
    false ->
      Parts ++ [list_to_binary(Data)]
  end.
