%% Copyright (c) 2012-2013, Aetrion LLC
%%
%% Permission to use, copy, modify, and/or distribute this software for any
%% purpose with or without fee is hereby granted, provided that the above
%% copyright notice and this permission notice appear in all copies.
%%
%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
%% WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
%% MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
%% ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
%% WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
%% ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
%% OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

%% @doc Process for parsing zone data from JSON to Erlang representations.
-module(erldns_zone_parser).

-behavior(gen_server).

-include_lib("dns/include/dns.hrl").
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
-define(PARSE_TIMEOUT, 30 * 1000).

-record(state, {parsers}).

%% Public API

start_link() ->
  gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% @doc Takes a JSON zone and turns it into the tuple {Name, Records}.
%%
%% The default timeout for parsing is currently 30 seconds.
zone_to_erlang(Zone) ->
  gen_server:call(?SERVER, {parse_zone, Zone}, ?PARSE_TIMEOUT).

%% @doc Register a list of custom parser modules.
-spec register_parsers([module()]) -> ok.
register_parsers(Modules) ->
  lager:info("Registering custom parsers: ~p", [Modules]),
  gen_server:call(?SERVER, {register_parsers, Modules}).

%% @doc Regiaer a custom parser module.
-spec register_parser(module()) -> ok.
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
  json_to_erlang([{<<"name">>, Name}, {<<"sha">>, ""}, {<<"records">>, JsonRecords}], Parsers);

json_to_erlang([{<<"name">>, Name}, {<<"sha">>, Sha}, {<<"records">>, JsonRecords}], Parsers) ->
  Records = lists:map(
    fun(JsonRecord) ->
        Data = json_record_to_list(JsonRecord),
        case json_record_to_erlang(Data) of
          {} -> try_custom_parsers(Data, Parsers);
          ParsedRecord -> ParsedRecord
        end
    end, JsonRecords),
  FilteredRecords = lists:filter(record_filter(), Records),
  DistinctRecords = lists:usort(FilteredRecords),
  {Name, Sha, DistinctRecords}.

record_filter() ->
  fun(R) ->
      case R of
        {} -> false;
        _ -> true
      end
  end.

json_record_to_list(JsonRecord) ->
  [
    proplists:get_value(<<"name">>, JsonRecord),
    proplists:get_value(<<"type">>, JsonRecord),
    proplists:get_value(<<"ttl">>, JsonRecord),
    proplists:get_value(<<"data">>, JsonRecord)
  ].

try_custom_parsers([_Name, _Type, _Ttl, _Rdata], []) ->
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
    data = #dns_rrdata_txt{txt = lists:flatten(erldns_txt:parse(proplists:get_value(<<"txt">>, Data)))},
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

json_record_to_erlang(_) ->
  {}.
