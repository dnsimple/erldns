%% Copyright (c) 2012-2018, DNSimple Corporation
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

-include_lib("dns_erlang/include/dns.hrl").
-include("erldns.hrl").

-export([
         start_link/0,
         zone_to_erlang/1,
         register_parsers/1,
         register_parser/1,
         list_parsers/0
        ]).

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

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-record(state, {parsers}).

%% Public API

%% @doc Start the parser processor.
-spec start_link() -> any().
start_link() ->
  gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% @doc Takes a JSON zone and turns it into the tuple {Name, Sha, Records}.
%%
%% The default timeout for parsing is currently 30 seconds.
-spec zone_to_erlang(binary()) -> {binary(), binary(), [dns:rr()], [erldns:keyset()]}.
zone_to_erlang(Zone) ->
  gen_server:call(?SERVER, {parse_zone, Zone}, ?PARSE_TIMEOUT).

%% @doc Register a list of custom parser modules.
-spec register_parsers([module()]) -> ok.
register_parsers(Modules) ->
  lager:info("Registering custom parsers (modules: ~p)", [Modules]),
  gen_server:call(?SERVER, {register_parsers, Modules}).

%% @doc Regiaer a custom parser module.
-spec register_parser(module()) -> ok.
register_parser(Module) ->
  lager:info("Registering custom parser (module: ~p)", [Module]),
  gen_server:call(?SERVER, {register_parser, Module}).

-spec list_parsers() -> [module()].
list_parsers() ->
  gen_server:call(?SERVER, list_parsers).


%% Gen server hooks
init([]) ->
  {ok, #state{parsers = []}}.

handle_call({parse_zone, Zone}, _From, State) ->
  {reply, json_to_erlang(Zone, State#state.parsers), State};

handle_call({register_parsers, Modules}, _From, State) ->
  {reply, ok, State#state{parsers = State#state.parsers ++ Modules}};

handle_call({register_parser, Module}, _From, State) ->
  {reply, ok, State#state{parsers = State#state.parsers ++ [Module]}};

handle_call(list_parsers, _From, State) ->
  {reply, ok, State#state.parsers}.

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
  json_to_erlang([{<<"name">>, Name}, {<<"sha">>, ""}, {<<"records">>, JsonRecords}, {<<"keys">>, []}], Parsers);

json_to_erlang([{<<"name">>, Name}, {<<"records">>, JsonRecords}, {<<"keys">>, JsonKeys}], Parsers) ->
  json_to_erlang([{<<"name">>, Name}, {<<"sha">>, ""}, {<<"records">>, JsonRecords}, {<<"keys">>, JsonKeys}], Parsers);

json_to_erlang([{<<"name">>, Name}, {<<"sha">>, Sha}, {<<"records">>, JsonRecords}], Parsers) ->
  json_to_erlang([{<<"name">>, Name}, {<<"sha">>, Sha}, {<<"records">>, JsonRecords}, {<<"keys">>, []}], Parsers);

json_to_erlang([{<<"name">>, Name}, {<<"sha">>, Sha}, {<<"records">>, JsonRecords}, {<<"keys">>, JsonKeys}], Parsers) ->
  Records = lists:map(
              fun(JsonRecord) ->
                  Data = json_record_to_list(JsonRecord),

                  % Filter by context
                  case apply_context_options(Data) of
                    pass ->
                      case json_record_to_erlang(Data) of
                        {} ->
                          case try_custom_parsers(Data, Parsers) of
                            {} ->
                                lager:warning("Unsupported record (data: ~p)", [Data]),
                                {};
                            ParsedRecord -> ParsedRecord
                          end;
                        ParsedRecord -> ParsedRecord
                      end;
                    _ ->
                      {}
                  end
              end, JsonRecords),
  FilteredRecords = lists:filter(record_filter(), Records),
  DistinctRecords = lists:usort(FilteredRecords),
  {Name, Sha, DistinctRecords, parse_json_keys(JsonKeys)}.

parse_json_keys(JsonKeys) -> parse_json_keys(JsonKeys, []).

parse_json_keys([], Keys) -> Keys;
parse_json_keys([[{<<"ksk">>, KskBin}, {<<"ksk_keytag">>, KskKeytag}, {<<"ksk_alg">>, KskAlg}, {<<"zsk">>, ZskBin}, {<<"zsk_keytag">>, ZskKeytag}, {<<"zsk_alg">>, ZskAlg}, {<<"inception">>, Inception}, {<<"until">>, ValidUntil}]|Rest], Keys) ->
  KeySet = #keyset{
              key_signing_key = to_crypto_key(KskBin),
              key_signing_key_tag = KskKeytag,
              key_signing_alg = KskAlg,
              zone_signing_key = to_crypto_key(ZskBin),
              zone_signing_key_tag = ZskKeytag,
              zone_signing_alg = ZskAlg,
              inception = iso8601:parse(Inception),
              valid_until = iso8601:parse(ValidUntil)
             },
  parse_json_keys(Rest, [KeySet | Keys]).

to_crypto_key(RsaKeyBin) ->
  % Where E is the public exponent, N is public modulus and D is the private exponent
  [_,_,M,E,N|_] = tuple_to_list(public_key:pem_entry_decode(lists:last(public_key:pem_decode(RsaKeyBin)))),
  [E,M,N].

record_filter() ->
  fun(R) ->
      case R of
        {} -> false;
        _ -> true
      end
  end.

-spec apply_context_list_check(sets:set(), sets:set()) -> [fail] | [pass].
apply_context_list_check(ContextAllowSet, ContextSet) ->
  case sets:size(sets:intersection(ContextAllowSet, ContextSet)) of
    0 -> [fail];
    _ -> [pass]
  end.

-spec apply_context_match_empty_check(boolean(), [any()]) -> [fail] | [pass].
apply_context_match_empty_check(true, []) -> [pass];
apply_context_match_empty_check(_, _) -> [fail].

%% Determine if a record should be used in this name server's context.
%%
%% If the context is undefined then the record will always be used.
%%
%% If the context is a list and has at least one condition that passes
%% then it will be included in the zone
-spec apply_context_options([any()]) -> pass | fail.
apply_context_options([_, _, _, _, undefined]) -> pass;
apply_context_options([_, _, _, _, Context]) ->
  case application:get_env(erldns, context_options) of
    {ok, ContextOptions} ->
      ContextSet = sets:from_list(Context),
      Result = lists:append([
                             apply_context_match_empty_check(erldns_config:keyget(match_empty, ContextOptions), Context),
                             apply_context_list_check(sets:from_list(erldns_config:keyget(allow, ContextOptions)), ContextSet)
                            ]),
      case lists:any(fun(I) -> I =:= pass end, Result) of
        true -> pass;
        _ -> fail
      end;
    _ ->
      pass
  end.

json_record_to_list(JsonRecord) ->
  [
   erldns_config:keyget(<<"name">>, JsonRecord),
   erldns_config:keyget(<<"type">>, JsonRecord),
   erldns_config:keyget(<<"ttl">>, JsonRecord),
   erldns_config:keyget(<<"data">>, JsonRecord),
   erldns_config:keyget(<<"context">>, JsonRecord)
  ].

try_custom_parsers([_Name, _Type, _Ttl, _Rdata, _Context], []) ->
  {};
try_custom_parsers(Data, [Parser|Rest]) ->
  case Parser:json_record_to_erlang(Data) of
    {} -> try_custom_parsers(Data, Rest);
    Record -> Record
  end.

% Internal converters
json_record_to_erlang([Name, Type, _Ttl, null, _]) ->
  lager:error("Record has null data (name: ~p, type: ~p)", [Name, Type]),
  {};

json_record_to_erlang([Name, <<"SOA">>, Ttl, Data, _Context]) ->
  #dns_rr{
     name = Name,
     type = ?DNS_TYPE_SOA,
     data = #dns_rrdata_soa{
               mname = erldns_config:keyget(<<"mname">>, Data),
               rname = erldns_config:keyget(<<"rname">>, Data),
               serial = erldns_config:keyget(<<"serial">>, Data),
               refresh = erldns_config:keyget(<<"refresh">>, Data),
               retry = erldns_config:keyget(<<"retry">>, Data),
               expire = erldns_config:keyget(<<"expire">>, Data),
               minimum = erldns_config:keyget(<<"minimum">>, Data)
              },
     ttl = Ttl};

json_record_to_erlang([Name, <<"NS">>, Ttl, Data, _Context]) ->
  #dns_rr{
     name = Name,
     type = ?DNS_TYPE_NS,
     data = #dns_rrdata_ns{
               dname = erldns_config:keyget(<<"dname">>, Data)
              },
     ttl = Ttl};

json_record_to_erlang([Name, <<"A">>, Ttl, Data, _Context]) ->
  Ip = erldns_config:keyget(<<"ip">>, Data),
  case inet_parse:address(binary_to_list(Ip)) of
    {ok, Address} ->
      #dns_rr{name = Name, type = ?DNS_TYPE_A, data = #dns_rrdata_a{ip = Address}, ttl = Ttl};
    {error, Reason} ->
      lager:error("Failed to parse A record address (ip: ~p, reason: ~p)", [Ip, Reason]),
      {}
  end;

json_record_to_erlang([Name, <<"AAAA">>, Ttl, Data, _Context]) ->
  Ip = erldns_config:keyget(<<"ip">>, Data),
  case inet_parse:address(binary_to_list(Ip)) of
    {ok, Address} ->
      #dns_rr{name = Name, type = ?DNS_TYPE_AAAA, data = #dns_rrdata_aaaa{ip = Address}, ttl = Ttl};
    {error, Reason} ->
      lager:error("Failed to parse AAAA record address (ip: ~p, reason: ~p)", [Ip, Reason]),
      {}
  end;

json_record_to_erlang([Name, <<"CAA">>, Ttl, Data, _Context]) ->
  #dns_rr{
     name = Name,
     type = ?DNS_TYPE_CAA,
     data = #dns_rrdata_caa{
               flags = erldns_config:keyget(<<"flags">>, Data),
               tag = erldns_config:keyget(<<"tag">>, Data),
               value = erldns_config:keyget(<<"value">>, Data)
              },
     ttl = Ttl};

json_record_to_erlang([Name, <<"CNAME">>, Ttl, Data, _Context]) ->
  #dns_rr{
     name = Name,
     type = ?DNS_TYPE_CNAME,
     data = #dns_rrdata_cname{dname = erldns_config:keyget(<<"dname">>, Data)},
     ttl = Ttl};

json_record_to_erlang([Name, <<"MX">>, Ttl, Data, _Context]) ->
  #dns_rr{
     name = Name,
     type = ?DNS_TYPE_MX,
     data = #dns_rrdata_mx{
               exchange = erldns_config:keyget(<<"exchange">>, Data),
               preference = erldns_config:keyget(<<"preference">>, Data)
              },
     ttl = Ttl};

json_record_to_erlang([Name, <<"HINFO">>, Ttl, Data, _Context]) ->
  #dns_rr{
     name = Name,
     type = ?DNS_TYPE_HINFO,
     data = #dns_rrdata_hinfo{
               cpu = erldns_config:keyget(<<"cpu">>, Data),
               os = erldns_config:keyget(<<"os">>, Data)
              },
     ttl = Ttl};

json_record_to_erlang([Name, <<"RP">>, Ttl, Data, _Context]) ->
  #dns_rr{
     name = Name,
     type = ?DNS_TYPE_RP,
     data = #dns_rrdata_rp{
               mbox = erldns_config:keyget(<<"mbox">>, Data),
               txt = erldns_config:keyget(<<"txt">>, Data)
              },
     ttl = Ttl};

json_record_to_erlang([Name, <<"TXT">>, Ttl, Data, _Context]) ->
  %% This function call may crash. Handle it as a bad record.
  try erldns_txt:parse(erldns_config:keyget(<<"txt">>, Data)) of
    ParsedText ->
      #dns_rr{
         name = Name,
         type = ?DNS_TYPE_TXT,
         data = #dns_rrdata_txt{txt = lists:flatten(ParsedText)},
         ttl = Ttl}
  catch
    Exception:Reason ->
      lager:error("Error parsing TXT (name: ~p, data: ~p, exception: ~p, reason: ~p)", [Name, Data, Exception, Reason])
  end;


json_record_to_erlang([Name, <<"SPF">>, Ttl, Data, _Context]) ->
  #dns_rr{
     name = Name,
     type = ?DNS_TYPE_SPF,
     data = #dns_rrdata_spf{spf = [erldns_config:keyget(<<"spf">>, Data)]},
     ttl = Ttl};

json_record_to_erlang([Name, <<"PTR">>, Ttl, Data, _Context]) ->
  #dns_rr{
     name = Name,
     type = ?DNS_TYPE_PTR,
     data = #dns_rrdata_ptr{dname = erldns_config:keyget(<<"dname">>, Data)},
     ttl = Ttl};

json_record_to_erlang([Name, <<"SSHFP">>, Ttl, Data, _Context]) ->
  %% This function call may crash. Handle it as a bad record.
  try hex_to_bin(erldns_config:keyget(<<"fp">>, Data)) of
    Fp ->
      #dns_rr{
         name = Name,
         type = ?DNS_TYPE_SSHFP,
         data = #dns_rrdata_sshfp{
                   alg = erldns_config:keyget(<<"alg">>, Data),
                   fp_type = erldns_config:keyget(<<"fptype">>, Data),
                   fp = Fp
                  },
         ttl = Ttl}
  catch
    Exception:Reason ->
      lager:error("Error parsing SSHFP (name: ~p, data: ~p, exception: ~p, reason: ~p)", [Name, Data, Exception, Reason]),
      {}
  end;

json_record_to_erlang([Name, <<"SRV">>, Ttl, Data, _Context]) ->
  #dns_rr{
     name = Name,
     type = ?DNS_TYPE_SRV,
     data = #dns_rrdata_srv{
               priority = erldns_config:keyget(<<"priority">>, Data),
               weight = erldns_config:keyget(<<"weight">>, Data),
               port = erldns_config:keyget(<<"port">>, Data),
               target = erldns_config:keyget(<<"target">>, Data)
              },
     ttl = Ttl};

json_record_to_erlang([Name, <<"NAPTR">>, Ttl, Data, _Context]) ->
  #dns_rr{
     name = Name,
     type = ?DNS_TYPE_NAPTR,
     data = #dns_rrdata_naptr{
               order = erldns_config:keyget(<<"order">>, Data),
               preference = erldns_config:keyget(<<"preference">>, Data),
               flags = erldns_config:keyget(<<"flags">>, Data),
               services = erldns_config:keyget(<<"services">>, Data),
               regexp = erldns_config:keyget(<<"regexp">>, Data),
               replacement = erldns_config:keyget(<<"replacement">>, Data)
              },
     ttl = Ttl};

json_record_to_erlang([Name, <<"DS">>, Ttl, Data, _Context]) ->
  try hex_to_bin(erldns_config:keyget(<<"digest">>, Data)) of
    Digest ->
      #dns_rr{
         name = Name,
         type = ?DNS_TYPE_DS,
         data = #dns_rrdata_ds{
                   keytag = erldns_config:keyget(<<"keytag">>, Data),
                   alg = erldns_config:keyget(<<"alg">>, Data),
                   digest_type = erldns_config:keyget(<<"digest_type">>, Data),
                   digest = Digest
                  },
         ttl = Ttl}
  catch
    Exception:Reason ->
      lager:error("Error parsing DS (name: ~p, data: ~p, exception: ~p, reason: ~p)", [Name, Data, Exception, Reason]),
      {}
  end;

json_record_to_erlang([Name, <<"CDS">>, Ttl, Data, _Context]) ->
  try hex_to_bin(erldns_config:keyget(<<"digest">>, Data)) of
    Digest ->
      #dns_rr{
         name = Name,
         type = ?DNS_TYPE_CDS,
         data = #dns_rrdata_cds{
                   keytag = erldns_config:keyget(<<"keytag">>, Data),
                   alg = erldns_config:keyget(<<"alg">>, Data),
                   digest_type = erldns_config:keyget(<<"digest_type">>, Data),
                   digest = Digest
                  },
         ttl = Ttl}
  catch
    Exception:Reason ->
      lager:error("Error parsing CDS (name: ~p, data: ~p, exception: ~p, reason: ~p)", [Name, Data, Exception, Reason]),
      {}
  end;

json_record_to_erlang([Name, <<"DNSKEY">>, Ttl, Data, _Context]) ->
  try base64_to_bin(erldns_config:keyget(<<"public_key">>, Data)) of
    PublicKey ->
      dnssec:add_keytag_to_dnskey(
        #dns_rr{
           name = Name,
           type = ?DNS_TYPE_DNSKEY,
           data = #dns_rrdata_dnskey{
                     flags = erldns_config:keyget(<<"flags">>, Data),
                     protocol = erldns_config:keyget(<<"protocol">>, Data),
                     alg = erldns_config:keyget(<<"alg">>, Data),
                     public_key = PublicKey
                    },
           ttl = Ttl})
  catch
    Exception:Reason ->
      lager:error("Error parsing DNSKEY (name: ~p, data: ~p, exception: ~p, reason: ~p)", [Name, Data, Exception, Reason]),
      {}
  end;

json_record_to_erlang([Name, <<"CDNSKEY">>, Ttl, Data, _Context]) ->
  try base64_to_bin(erldns_config:keyget(<<"public_key">>, Data)) of
    PublicKey ->
      dnssec:add_keytag_to_cdnskey(
        #dns_rr{
           name = Name,
           type = ?DNS_TYPE_CDNSKEY,
           data = #dns_rrdata_cdnskey{
                     flags = erldns_config:keyget(<<"flags">>, Data),
                     protocol = erldns_config:keyget(<<"protocol">>, Data),
                     alg = erldns_config:keyget(<<"alg">>, Data),
                     public_key = PublicKey
                    },
           ttl = Ttl})
  catch
    Exception:Reason ->
      lager:error("Error parsing CDNSKEY (name: ~p, data: ~p, exception: ~p, reason: ~p)", [Name, Data, Exception, Reason]),
      {}
  end;

json_record_to_erlang(_Data) ->
  {}.

hex_to_bin(Bin) when is_binary(Bin) ->
  Fun = fun(A, B) ->
            case io_lib:fread("~16u", [A, B]) of
              {ok, [V], []} -> V;
              _ -> error(badarg)
            end
        end,
  << <<(Fun(A,B))>> || <<A, B>> <= Bin >>.

base64_to_bin(Bin) when is_binary(Bin) ->
  base64:decode(Bin).

-ifdef(TEST).
json_record_to_erlang_test() ->
  Name = <<"example.com">>,
  ?assertEqual({}, json_record_to_erlang([])),
  ?assertEqual({}, json_record_to_erlang([Name, <<"SOA">>, 3600, null, null])).

json_record_soa_to_erlang_test() ->
  Name = <<"example.com">>,
  ?assertEqual(#dns_rr{name = Name,
                       type = ?DNS_TYPE_SOA,
                       data = #dns_rrdata_soa{
                                 mname = <<"ns1.example.com">>,
                                 rname = <<"admin.example.com">>,
                                 serial = 12345,
                                 refresh = 555,
                                 retry = 666,
                                 expire = 777,
                                 minimum = 888
                                },
                       ttl = 3600},
               json_record_to_erlang([Name, <<"SOA">>, 3600, [
                                                              {<<"mname">>, <<"ns1.example.com">>},
                                                              {<<"rname">>, <<"admin.example.com">>},
                                                              {<<"serial">>, 12345},
                                                              {<<"refresh">>, 555},
                                                              {<<"retry">>, 666},
                                                              {<<"expire">>, 777},
                                                              {<<"minimum">>, 888}
                                                             ], undefined])).

json_record_ns_to_erlang_test() ->
  Name = <<"example.com">>,
  ?assertEqual(#dns_rr{name = Name,
                       type = ?DNS_TYPE_NS,
                       data = #dns_rrdata_ns{
                                 dname = <<"ns1.example.com">>
                                },
                       ttl = 3600},
               json_record_to_erlang([Name, <<"NS">>, 3600, [
                                                             {<<"dname">>, <<"ns1.example.com">>}
                                                            ], undefined])).

json_record_a_to_erlang_test() ->
  Name = <<"example.com">>,
  ?assertEqual(#dns_rr{name = Name,
                       type = ?DNS_TYPE_A,
                       data = #dns_rrdata_a{
                                 ip = {1,2,3,4}
                                },
                       ttl = 3600},
               json_record_to_erlang([Name, <<"A">>, 3600, [
                                                            {<<"ip">>, <<"1.2.3.4">>}
                                                           ], undefined])).

json_record_aaaa_to_erlang_test() ->
  Name = <<"example.com">>,
  ?assertEqual(#dns_rr{name = Name,
                       type = ?DNS_TYPE_AAAA,
                       data = #dns_rrdata_aaaa{
                                 ip = {0,0,0,0,0,0,0,1}
                                },
                       ttl = 3600},
               json_record_to_erlang([Name, <<"AAAA">>, 3600, [
                                                               {<<"ip">>, <<"::1">>}
                                                              ], undefined])).

json_record_cds_to_erlang_test() ->
  Name = <<"example-dnssec.com">>,
  ?assertEqual(#dns_rr{name = Name,
                       type = ?DNS_TYPE_CDS,
                       data = #dns_rrdata_cds{
                                  keytag = 0,
                                  digest_type = 2,
                                  alg = 8,
                                  digest = hex_to_bin(<<"4315A7AD09AE0BEBA6CC3104BBCD88000ED796887F1C4D520A3A608D715B72CA">>)
                                },
                       ttl = 3600},
               json_record_to_erlang([Name, <<"CDS">>, 3600, [
                                                              {<<"keytag">>, 0},
                                                              {<<"digest_type">>, 2},
                                                              {<<"alg">>, 8},
                                                              {<<"digest">>, <<"4315A7AD09AE0BEBA6CC3104BBCD88000ED796887F1C4D520A3A608D715B72CA">>}
                                                             ], undefined])).

hex_to_bin_test() ->
  ?assertEqual(<<"">>, hex_to_bin(<<"">>)),
  ?assertEqual(<<255, 0, 255>>, hex_to_bin(<<"FF00FF">>)).

base64_to_bin_test() ->
  ?assertEqual(<<"">>, base64_to_bin(<<"">>)),
  ?assertEqual(<<3,1,0,1,191,165,76,56,217,9,250,187,15,147,125,112,215,
                 117,186,13,244,192,186,219,9,112,125,153,82,73,64,105,
                 80,64,122,98,28,121,76,104,177,134,177,93,191,143,159,
                 158,162,49,233,249,100,20,204,218,78,206,181,11,23,169,
                 172,108,75,212,185,93,160,72,73,233,110,231,145,87,139,
                 112,59,201,174,24,79,177,121,75,172,121,42,7,135,246,
                 147,164,15,25,245,35,238,109,189,53,153,219,170,169,165,
                 4,55,146,110,207,100,56,132,93,29,73,68,137,98,82,79,42,
                 26,122,54,179,160,161,236,163>>, base64_to_bin(<<"AwEAAb+lTDjZCfq7D5N9cNd1ug30wLrbCXB9mVJJQGlQQHpiHHlMaLGGsV2/j5+eojHp+WQUzNpOzrULF6msbEvUuV2gSEnpbueRV4twO8muGE+xeUuseSoHh/aTpA8Z9SPubb01mduqqaUEN5Juz2Q4hF0dSUSJYlJPKhp6NrOgoeyj">>)).
-endif.
