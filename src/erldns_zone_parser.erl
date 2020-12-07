%% Copyright (c) 2012-2020, DNSimple Corporation
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

-export([start_link/0,
         zone_to_erlang/1,
         register_parsers/1,
         register_parser/1,
         list_parsers/0]).
% Gen server hooks
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

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

%% @doc Register a custom parser module.
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
json_to_erlang(Zone, Parsers) when is_map(Zone) ->
    Name = maps:get(<<"name">>, Zone),
    Sha = maps:get(<<"sha">>, Zone, ""),
    JsonRecords = maps:get(<<"records">>, Zone),
    JsonKeys = maps:get(<<"keys">>, Zone, []),
    Records =
        lists:map(fun(JsonRecord) ->
                     Data = json_record_to_list(JsonRecord),
                     % Filter by context
                     case apply_context_options(Data) of
                         pass ->
                             case json_record_to_erlang(Data) of
                                 {} ->
                                     case try_custom_parsers(Data, Parsers) of
                                         {} ->
                                             erldns_events:notify({?MODULE, unsupported_record, Data}),
                                             {};
                                         ParsedRecord -> ParsedRecord
                                     end;
                                 ParsedRecord -> ParsedRecord
                             end;
                         _ -> {}
                     end
                  end,
                  JsonRecords),
    FilteredRecords = lists:filter(record_filter(), Records),
    DistinctRecords = lists:usort(FilteredRecords),
    {Name, Sha, DistinctRecords, parse_json_keys_as_maps(JsonKeys)};
json_to_erlang(Zone, Parsers) ->
    Name = proplists:get_value(<<"name">>, Zone),
    Sha = proplists:get_value(<<"sha">>, Zone, ""),
    JsonRecords = proplists:get_value(<<"records">>, Zone),
    JsonKeys = proplists:get_value(<<"keys">>, Zone, []),
    Records =
        lists:map(fun(JsonRecord) ->
                     Data = json_record_to_list(JsonRecord),
                     % Filter by context
                     case apply_context_options(Data) of
                         pass ->
                             case json_record_to_erlang(Data) of
                                 {} ->
                                     case try_custom_parsers(Data, Parsers) of
                                         {} ->
                                             erldns_events:notify({?MODULE, unsupported_record, Data}),
                                             {};
                                         ParsedRecord -> ParsedRecord
                                     end;
                                 ParsedRecord -> ParsedRecord
                             end;
                         _ -> {}
                     end
                  end,
                  JsonRecords),
    FilteredRecords = lists:filter(record_filter(), Records),
    DistinctRecords = lists:usort(FilteredRecords),
    {Name, Sha, DistinctRecords, parse_json_keys(JsonKeys)}.

parse_json_keys_as_maps([]) ->
    [];
parse_json_keys_as_maps(JsonKeys) ->
    parse_json_keys_as_maps(JsonKeys, []).

parse_json_keys_as_maps([], Keys) ->
    Keys;
parse_json_keys_as_maps([Key | Rest], Keys) ->
    KeySet =
        #keyset{key_signing_key = to_crypto_key(maps:get(<<"ksk">>, Key)),
                key_signing_key_tag = maps:get(<<"ksk_keytag">>, Key),
                key_signing_alg = maps:get(<<"ksk_alg">>, Key),
                zone_signing_key = to_crypto_key(maps:get(<<"zsk">>, Key)),
                zone_signing_key_tag = maps:get(<<"zsk_keytag">>, Key),
                zone_signing_alg = maps:get(<<"zsk_alg">>, Key),
                inception = iso8601:parse(maps:get(<<"inception">>, Key)),
                valid_until = iso8601:parse(maps:get(<<"until">>, Key))},
    parse_json_keys_as_maps(Rest, [KeySet | Keys]).

parse_json_keys([]) ->
    [];
parse_json_keys(JsonKeys) ->
    parse_json_keys(JsonKeys, []).

%% as JSON key order is undefined, we need to ensure that the list of
%% proplists only contains proplists that are already sorted by key, so
%% that the pattern-match can succeed (or fail) in a single pass.
parse_json_keys([], Keys) ->
    Keys;
parse_json_keys([[%% pre-sorting the proplist allows us to pattern-match
                  {<<"inception">>, Inception},
                  {<<"ksk">>, KskBin},
                  {<<"ksk_alg">>, KskAlg},
                  {<<"ksk_keytag">>, KskKeytag},
                  {<<"until">>, ValidUntil},
                  {<<"zsk">>, ZskBin},
                  {<<"zsk_alg">>, ZskAlg},
                  {<<"zsk_keytag">>, ZskKeytag}]
                 | Rest],
                Keys) ->
    KeySet =
        #keyset{key_signing_key = to_crypto_key(KskBin),
                key_signing_key_tag = KskKeytag,
                key_signing_alg = KskAlg,
                zone_signing_key = to_crypto_key(ZskBin),
                zone_signing_key_tag = ZskKeytag,
                zone_signing_alg = ZskAlg,
                inception = iso8601:parse(Inception),
                valid_until = iso8601:parse(ValidUntil)},
    parse_json_keys(Rest, [KeySet | Keys]);
%% pre-sort the proplist, to be consumed in previous pattern match
parse_json_keys([Proplist], Acc) ->
    parse_json_keys([lists:sort(Proplist)], Acc).

to_crypto_key(RsaKeyBin) ->
    % Where E is the public exponent, N is public modulus and D is the private exponent
    [_, _, M, E, N | _] = tuple_to_list(public_key:pem_entry_decode(lists:last(public_key:pem_decode(RsaKeyBin)))),
    [E, M, N].

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
        0 ->
            [fail];
        _ ->
            [pass]
    end.

-spec apply_context_match_empty_check(boolean(), [any()]) -> [fail] | [pass].
apply_context_match_empty_check(true, []) ->
    [pass];
apply_context_match_empty_check(_, _) ->
    [fail].

%% Determine if a record should be used in this name server's context.
%%
%% If the context is undefined then the record will always be used.
%%
%% If the context is a list and has at least one condition that passes
%% then it will be included in the zone
-spec apply_context_options([any()]) -> pass | fail.
apply_context_options([_, _, _, _, undefined]) ->
    pass;
apply_context_options([_, _, _, _, Context]) ->
    case application:get_env(erldns, context_options) of
        {ok, ContextOptions} ->
            ContextSet = sets:from_list(Context),
            Result =
                lists:append([apply_context_match_empty_check(erldns_config:keyget(match_empty, ContextOptions), Context),
                              apply_context_list_check(sets:from_list(erldns_config:keyget(allow, ContextOptions)), ContextSet)]),
            case lists:any(fun(I) -> I =:= pass end, Result) of
                true ->
                    pass;
                _ ->
                    fail
            end;
        _ ->
            pass
    end.

json_record_to_list(JsonRecord) when is_map(JsonRecord) ->
    [maps:get(<<"name">>, JsonRecord),
     maps:get(<<"type">>, JsonRecord),
     maps:get(<<"ttl">>, JsonRecord),
     maps:get(<<"data">>, JsonRecord),
     maps:get(<<"context">>, JsonRecord)];
json_record_to_list(JsonRecord) ->
    [erldns_config:keyget(<<"name">>, JsonRecord),
     erldns_config:keyget(<<"type">>, JsonRecord),
     erldns_config:keyget(<<"ttl">>, JsonRecord),
     erldns_config:keyget(<<"data">>, JsonRecord),
     erldns_config:keyget(<<"context">>, JsonRecord)].

try_custom_parsers([_Name, _Type, _Ttl, _Rdata, _Context], []) ->
    {};
try_custom_parsers(Data, [Parser | Rest]) ->
    case Parser:json_record_to_erlang(Data) of
        {} ->
            try_custom_parsers(Data, Rest);
        Record ->
            Record
    end.

% Internal converters
json_record_to_erlang([Name, Type, _Ttl, Data = null, _]) ->
    erldns_events:notify({?MODULE, error, {Name, Type, Data, null_data}}),
    {};
json_record_to_erlang([Name, <<"SOA">>, Ttl, Data, _]) when is_map(Data) ->
    #dns_rr{name = Name,
            type = ?DNS_TYPE_SOA,
            data =
                #dns_rrdata_soa{mname = maps:get(<<"mname">>, Data),
                                rname = maps:get(<<"rname">>, Data),
                                serial = maps:get(<<"serial">>, Data),
                                refresh = maps:get(<<"refresh">>, Data),
                                retry = maps:get(<<"retry">>, Data),
                                expire = maps:get(<<"expire">>, Data),
                                minimum = maps:get(<<"minimum">>, Data)},
            ttl = Ttl};
json_record_to_erlang([Name, <<"SOA">>, Ttl, Data, _Context]) ->
    #dns_rr{name = Name,
            type = ?DNS_TYPE_SOA,
            data =
                #dns_rrdata_soa{mname = erldns_config:keyget(<<"mname">>, Data),
                                rname = erldns_config:keyget(<<"rname">>, Data),
                                serial = erldns_config:keyget(<<"serial">>, Data),
                                refresh = erldns_config:keyget(<<"refresh">>, Data),
                                retry = erldns_config:keyget(<<"retry">>, Data),
                                expire = erldns_config:keyget(<<"expire">>, Data),
                                minimum = erldns_config:keyget(<<"minimum">>, Data)},
            ttl = Ttl};
json_record_to_erlang([Name, <<"NS">>, Ttl, Data, _Context]) when is_map(Data) ->
    #dns_rr{name = Name,
            type = ?DNS_TYPE_NS,
            data = #dns_rrdata_ns{dname = maps:get(<<"dname">>, Data)},
            ttl = Ttl};
json_record_to_erlang([Name, <<"NS">>, Ttl, Data, _Context]) ->
    #dns_rr{name = Name,
            type = ?DNS_TYPE_NS,
            data = #dns_rrdata_ns{dname = erldns_config:keyget(<<"dname">>, Data)},
            ttl = Ttl};
json_record_to_erlang([Name, Type = <<"A">>, Ttl, Data, _Context]) when is_map(Data) ->
    case inet_parse:address(binary_to_list(maps:get(<<"ip">>, Data))) of
        {ok, Address} ->
            #dns_rr{name = Name,
                    type = ?DNS_TYPE_A,
                    data = #dns_rrdata_a{ip = Address},
                    ttl = Ttl};
        {error, Reason} ->
            erldns_events:notify({?MODULE, error, {Name, Type, Data, Reason}}),
            {}
    end;
json_record_to_erlang([Name, Type = <<"A">>, Ttl, Data, _Context]) ->
    case inet_parse:address(binary_to_list(erldns_config:keyget(<<"ip">>, Data))) of
        {ok, Address} ->
            #dns_rr{name = Name,
                    type = ?DNS_TYPE_A,
                    data = #dns_rrdata_a{ip = Address},
                    ttl = Ttl};
        {error, Reason} ->
            erldns_events:notify({?MODULE, error, {Name, Type, Data, Reason}}),
            {}
    end;
json_record_to_erlang([Name, Type = <<"AAAA">>, Ttl, Data, _Context]) when is_map(Data) ->
    case inet_parse:address(binary_to_list(maps:get(<<"ip">>, Data))) of
        {ok, Address} ->
            #dns_rr{name = Name,
                    type = ?DNS_TYPE_AAAA,
                    data = #dns_rrdata_aaaa{ip = Address},
                    ttl = Ttl};
        {error, Reason} ->
            erldns_events:notify({?MODULE, error, {Name, Type, Data, Reason}}),
            {}
    end;
json_record_to_erlang([Name, Type = <<"AAAA">>, Ttl, Data, _Context]) ->
    case inet_parse:address(binary_to_list(erldns_config:keyget(<<"ip">>, Data))) of
        {ok, Address} ->
            #dns_rr{name = Name,
                    type = ?DNS_TYPE_AAAA,
                    data = #dns_rrdata_aaaa{ip = Address},
                    ttl = Ttl};
        {error, Reason} ->
            erldns_events:notify({?MODULE, error, {Name, Type, Data, Reason}}),
            {}
    end;
json_record_to_erlang([Name, <<"CAA">>, Ttl, Data, _Context]) when is_map(Data) ->
    #dns_rr{name = Name,
            type = ?DNS_TYPE_CAA,
            data =
                #dns_rrdata_caa{flags = maps:get(<<"flags">>, Data),
                                tag = maps:get(<<"tag">>, Data),
                                value = maps:get(<<"value">>, Data)},
            ttl = Ttl};
json_record_to_erlang([Name, <<"CAA">>, Ttl, Data, _Context]) ->
    #dns_rr{name = Name,
            type = ?DNS_TYPE_CAA,
            data =
                #dns_rrdata_caa{flags = erldns_config:keyget(<<"flags">>, Data),
                                tag = erldns_config:keyget(<<"tag">>, Data),
                                value = erldns_config:keyget(<<"value">>, Data)},
            ttl = Ttl};
json_record_to_erlang([Name, <<"CNAME">>, Ttl, Data, _Context]) when is_map(Data) ->
    #dns_rr{name = Name,
            type = ?DNS_TYPE_CNAME,
            data = #dns_rrdata_cname{dname = maps:get(<<"dname">>, Data)},
            ttl = Ttl};
json_record_to_erlang([Name, <<"CNAME">>, Ttl, Data, _Context]) ->
    #dns_rr{name = Name,
            type = ?DNS_TYPE_CNAME,
            data = #dns_rrdata_cname{dname = erldns_config:keyget(<<"dname">>, Data)},
            ttl = Ttl};
json_record_to_erlang([Name, <<"MX">>, Ttl, Data, _Context]) when is_map(Data) ->
    #dns_rr{name = Name,
            type = ?DNS_TYPE_MX,
            data = #dns_rrdata_mx{exchange = maps:get(<<"exchange">>, Data), preference = maps:get(<<"preference">>, Data)},
            ttl = Ttl};
json_record_to_erlang([Name, <<"MX">>, Ttl, Data, _Context]) ->
    #dns_rr{name = Name,
            type = ?DNS_TYPE_MX,
            data = #dns_rrdata_mx{exchange = erldns_config:keyget(<<"exchange">>, Data), preference = erldns_config:keyget(<<"preference">>, Data)},
            ttl = Ttl};
json_record_to_erlang([Name, <<"HINFO">>, Ttl, Data, _Context]) when is_map(Data) ->
    #dns_rr{name = Name,
            type = ?DNS_TYPE_HINFO,
            data = #dns_rrdata_hinfo{cpu = maps:get(<<"cpu">>, Data), os = maps:get(<<"os">>, Data)},
            ttl = Ttl};
json_record_to_erlang([Name, <<"HINFO">>, Ttl, Data, _Context]) ->
    #dns_rr{name = Name,
            type = ?DNS_TYPE_HINFO,
            data = #dns_rrdata_hinfo{cpu = erldns_config:keyget(<<"cpu">>, Data), os = erldns_config:keyget(<<"os">>, Data)},
            ttl = Ttl};
json_record_to_erlang([Name, <<"RP">>, Ttl, Data, _Context]) when is_map(Data) ->
    #dns_rr{name = Name,
            type = ?DNS_TYPE_RP,
            data = #dns_rrdata_rp{mbox = maps:get(<<"mbox">>, Data), txt = maps:get(<<"txt">>, Data)},
            ttl = Ttl};
json_record_to_erlang([Name, <<"RP">>, Ttl, Data, _Context]) ->
    #dns_rr{name = Name,
            type = ?DNS_TYPE_RP,
            data = #dns_rrdata_rp{mbox = erldns_config:keyget(<<"mbox">>, Data), txt = erldns_config:keyget(<<"txt">>, Data)},
            ttl = Ttl};
json_record_to_erlang([Name, Type = <<"TXT">>, Ttl, Data, _Context]) when is_map(Data) ->
    %% This function call may crash. Handle it as a bad record.
    try erldns_txt:parse(maps:get(<<"txt">>, Data)) of
        ParsedText ->
            #dns_rr{name = Name,
                    type = ?DNS_TYPE_TXT,
                    data = #dns_rrdata_txt{txt = lists:flatten(ParsedText)},
                    ttl = Ttl}
    catch
        Exception:Reason ->
            erldns_events:notify({?MODULE, error, {Name, Type, Data, Exception, Reason}}),
            {}
    end;
json_record_to_erlang([Name, Type = <<"TXT">>, Ttl, Data, _Context]) ->
    %% This function call may crash. Handle it as a bad record.
    try erldns_txt:parse(erldns_config:keyget(<<"txt">>, Data)) of
        ParsedText ->
            #dns_rr{name = Name,
                    type = ?DNS_TYPE_TXT,
                    data = #dns_rrdata_txt{txt = lists:flatten(ParsedText)},
                    ttl = Ttl}
    catch
        Exception:Reason ->
            erldns_events:notify({?MODULE, error, {Name, Type, Data, Exception, Reason}}),
            {}
    end;
json_record_to_erlang([Name, <<"SPF">>, Ttl, Data, _Context]) when is_map(Data) ->
    #dns_rr{name = Name,
            type = ?DNS_TYPE_SPF,
            data = #dns_rrdata_spf{spf = [maps:get(<<"spf">>, Data)]},
            ttl = Ttl};
json_record_to_erlang([Name, <<"SPF">>, Ttl, Data, _Context]) ->
    #dns_rr{name = Name,
            type = ?DNS_TYPE_SPF,
            data = #dns_rrdata_spf{spf = [erldns_config:keyget(<<"spf">>, Data)]},
            ttl = Ttl};
json_record_to_erlang([Name, <<"PTR">>, Ttl, Data, _Context]) when is_map(Data) ->
    #dns_rr{name = Name,
            type = ?DNS_TYPE_PTR,
            data = #dns_rrdata_ptr{dname = maps:get(<<"dname">>, Data)},
            ttl = Ttl};
json_record_to_erlang([Name, <<"PTR">>, Ttl, Data, _Context]) ->
    #dns_rr{name = Name,
            type = ?DNS_TYPE_PTR,
            data = #dns_rrdata_ptr{dname = erldns_config:keyget(<<"dname">>, Data)},
            ttl = Ttl};
json_record_to_erlang([Name, Type = <<"SSHFP">>, Ttl, Data, _Context]) when is_map(Data) ->
    %% This function call may crash. Handle it as a bad record.
    try hex_to_bin(maps:get(<<"fp">>, Data)) of
        Fp ->
            #dns_rr{name = Name,
                    type = ?DNS_TYPE_SSHFP,
                    data =
                        #dns_rrdata_sshfp{alg = maps:get(<<"alg">>, Data),
                                          fp_type = maps:get(<<"fptype">>, Data),
                                          fp = Fp},
                    ttl = Ttl}
    catch
        Exception:Reason ->
            erldns_events:notify({?MODULE, error, {Name, Type, Data, Exception, Reason}}),
            {}
    end;
json_record_to_erlang([Name, Type = <<"SSHFP">>, Ttl, Data, _Context]) ->
    %% This function call may crash. Handle it as a bad record.
    try hex_to_bin(erldns_config:keyget(<<"fp">>, Data)) of
        Fp ->
            #dns_rr{name = Name,
                    type = ?DNS_TYPE_SSHFP,
                    data =
                        #dns_rrdata_sshfp{alg = erldns_config:keyget(<<"alg">>, Data),
                                          fp_type = erldns_config:keyget(<<"fptype">>, Data),
                                          fp = Fp},
                    ttl = Ttl}
    catch
        Exception:Reason ->
            erldns_events:notify({?MODULE, error, {Name, Type, Data, Exception, Reason}}),
            {}
    end;
json_record_to_erlang([Name, <<"SRV">>, Ttl, Data, _Context]) when is_map(Data) ->
    #dns_rr{name = Name,
            type = ?DNS_TYPE_SRV,
            data =
                #dns_rrdata_srv{priority = maps:get(<<"priority">>, Data),
                                weight = maps:get(<<"weight">>, Data),
                                port = maps:get(<<"port">>, Data),
                                target = maps:get(<<"target">>, Data)},
            ttl = Ttl};
json_record_to_erlang([Name, <<"SRV">>, Ttl, Data, _Context]) ->
    #dns_rr{name = Name,
            type = ?DNS_TYPE_SRV,
            data =
                #dns_rrdata_srv{priority = erldns_config:keyget(<<"priority">>, Data),
                                weight = erldns_config:keyget(<<"weight">>, Data),
                                port = erldns_config:keyget(<<"port">>, Data),
                                target = erldns_config:keyget(<<"target">>, Data)},
            ttl = Ttl};
json_record_to_erlang([Name, <<"NAPTR">>, Ttl, Data, _Context]) when is_map(Data) ->
    #dns_rr{name = Name,
            type = ?DNS_TYPE_NAPTR,
            data =
                #dns_rrdata_naptr{order = maps:get(<<"order">>, Data),
                                  preference = maps:get(<<"preference">>, Data),
                                  flags = maps:get(<<"flags">>, Data),
                                  services = maps:get(<<"services">>, Data),
                                  regexp = maps:get(<<"regexp">>, Data),
                                  replacement = maps:get(<<"replacement">>, Data)},
            ttl = Ttl};
json_record_to_erlang([Name, <<"NAPTR">>, Ttl, Data, _Context]) ->
    #dns_rr{name = Name,
            type = ?DNS_TYPE_NAPTR,
            data =
                #dns_rrdata_naptr{order = erldns_config:keyget(<<"order">>, Data),
                                  preference = erldns_config:keyget(<<"preference">>, Data),
                                  flags = erldns_config:keyget(<<"flags">>, Data),
                                  services = erldns_config:keyget(<<"services">>, Data),
                                  regexp = erldns_config:keyget(<<"regexp">>, Data),
                                  replacement = erldns_config:keyget(<<"replacement">>, Data)},
            ttl = Ttl};
json_record_to_erlang([Name, Type = <<"DS">>, Ttl, Data, _Context]) when is_map(Data) ->
    try hex_to_bin(maps:get(<<"digest">>, Data)) of
        Digest ->
            #dns_rr{name = Name,
                    type = ?DNS_TYPE_DS,
                    data =
                        #dns_rrdata_ds{keytag = maps:get(<<"keytag">>, Data),
                                       alg = maps:get(<<"alg">>, Data),
                                       digest_type = maps:get(<<"digest_type">>, Data),
                                       digest = Digest},
                    ttl = Ttl}
    catch
        Exception:Reason ->
            erldns_events:notify({?MODULE, error, {Name, Type, Data, Exception, Reason}}),
            {}
    end;
json_record_to_erlang([Name, Type = <<"DS">>, Ttl, Data, _Context]) ->
    try hex_to_bin(erldns_config:keyget(<<"digest">>, Data)) of
        Digest ->
            #dns_rr{name = Name,
                    type = ?DNS_TYPE_DS,
                    data =
                        #dns_rrdata_ds{keytag = erldns_config:keyget(<<"keytag">>, Data),
                                       alg = erldns_config:keyget(<<"alg">>, Data),
                                       digest_type = erldns_config:keyget(<<"digest_type">>, Data),
                                       digest = Digest},
                    ttl = Ttl}
    catch
        Exception:Reason ->
            erldns_events:notify({?MODULE, error, {Name, Type, Data, Exception, Reason}}),
            {}
    end;
json_record_to_erlang([Name, Type = <<"CDS">>, Ttl, Data, _Context]) when is_map(Data) ->
    try hex_to_bin(maps:get(<<"digest">>, Data)) of
        Digest ->
            #dns_rr{name = Name,
                    type = ?DNS_TYPE_CDS,
                    data =
                        #dns_rrdata_cds{keytag = maps:get(<<"keytag">>, Data),
                                        alg = maps:get(<<"alg">>, Data),
                                        digest_type = maps:get(<<"digest_type">>, Data),
                                        digest = Digest},
                    ttl = Ttl}
    catch
        Exception:Reason ->
            erldns_events:notify({?MODULE, error, {Name, Type, Data, Exception, Reason}}),
            {}
    end;
json_record_to_erlang([Name, Type = <<"CDS">>, Ttl, Data, _Context]) ->
    try hex_to_bin(erldns_config:keyget(<<"digest">>, Data)) of
        Digest ->
            #dns_rr{name = Name,
                    type = ?DNS_TYPE_CDS,
                    data =
                        #dns_rrdata_cds{keytag = erldns_config:keyget(<<"keytag">>, Data),
                                        alg = erldns_config:keyget(<<"alg">>, Data),
                                        digest_type = erldns_config:keyget(<<"digest_type">>, Data),
                                        digest = Digest},
                    ttl = Ttl}
    catch
        Exception:Reason ->
            erldns_events:notify({?MODULE, error, {Name, Type, Data, Exception, Reason}}),
            {}
    end;
json_record_to_erlang([Name, Type = <<"DNSKEY">>, Ttl, Data, _Context]) when is_map(Data) ->
    try base64_to_bin(maps:get(<<"public_key">>, Data)) of
        PublicKey ->
            dnssec:add_keytag_to_dnskey(#dns_rr{name = Name,
                                                type = ?DNS_TYPE_DNSKEY,
                                                data =
                                                    #dns_rrdata_dnskey{flags = maps:get(<<"flags">>, Data),
                                                                       protocol = maps:get(<<"protocol">>, Data),
                                                                       alg = maps:get(<<"alg">>, Data),
                                                                       public_key = PublicKey},
                                                ttl = Ttl})
    catch
        Exception:Reason ->
            erldns_events:notify({?MODULE, error, {Name, Type, Data, Exception, Reason}}),
            {}
    end;
json_record_to_erlang([Name, Type = <<"DNSKEY">>, Ttl, Data, _Context]) ->
    try base64_to_bin(erldns_config:keyget(<<"public_key">>, Data)) of
        PublicKey ->
            dnssec:add_keytag_to_dnskey(#dns_rr{name = Name,
                                                type = ?DNS_TYPE_DNSKEY,
                                                data =
                                                    #dns_rrdata_dnskey{flags = erldns_config:keyget(<<"flags">>, Data),
                                                                       protocol = erldns_config:keyget(<<"protocol">>, Data),
                                                                       alg = erldns_config:keyget(<<"alg">>, Data),
                                                                       public_key = PublicKey},
                                                ttl = Ttl})
    catch
        Exception:Reason ->
            erldns_events:notify({?MODULE, error, {Name, Type, Data, Exception, Reason}}),
            {}
    end;
json_record_to_erlang([Name, Type = <<"CDNSKEY">>, Ttl, Data, _Context]) when is_map(Data) ->
    try base64_to_bin(maps:get(<<"public_key">>, Data)) of
        PublicKey ->
            dnssec:add_keytag_to_cdnskey(#dns_rr{name = Name,
                                                 type = ?DNS_TYPE_CDNSKEY,
                                                 data =
                                                     #dns_rrdata_cdnskey{flags = maps:get(<<"flags">>, Data),
                                                                         protocol = maps:get(<<"protocol">>, Data),
                                                                         alg = maps:get(<<"alg">>, Data),
                                                                         public_key = PublicKey},
                                                 ttl = Ttl})
    catch
        Exception:Reason ->
            erldns_events:notify({?MODULE, error, {Name, Type, Data, Exception, Reason}}),
            {}
    end;
json_record_to_erlang([Name, Type = <<"CDNSKEY">>, Ttl, Data, _Context]) ->
    try base64_to_bin(erldns_config:keyget(<<"public_key">>, Data)) of
        PublicKey ->
            dnssec:add_keytag_to_cdnskey(#dns_rr{name = Name,
                                                 type = ?DNS_TYPE_CDNSKEY,
                                                 data =
                                                     #dns_rrdata_cdnskey{flags = erldns_config:keyget(<<"flags">>, Data),
                                                                         protocol = erldns_config:keyget(<<"protocol">>, Data),
                                                                         alg = erldns_config:keyget(<<"alg">>, Data),
                                                                         public_key = PublicKey},
                                                 ttl = Ttl})
    catch
        Exception:Reason ->
            erldns_events:notify({?MODULE, error, {Name, Type, Data, Exception, Reason}}),
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
    << <<(Fun(A, B))>> || <<A, B>> <= Bin >>.

base64_to_bin(Bin) when is_binary(Bin) ->
    base64:decode(Bin).

-ifdef(TEST).

json_to_erlang_test() ->
    json_to_erlang(jsx:decode(<<"{\"name\":\"example.com\",\"sha\":\"10ea56ad7be9d3e6e75be3a15ef0dfabe9facafba486d74914e7baf8fb36638e\",\"rec"
                                "ords\":[{\"name\":\"example.com\",\"type\":\"SOA\",\"data\":{\"mname\":\"ns1.dnsimple.com\",\"rname\":\"admi"
                                "n.dnsimple.com\",\"serial\":1597990915,\"refresh\":86400,\"retry\":7200,\"expire\":604800,\"minimum\":300},\""
                                "ttl\":3600,\"context\":[\"anycast\"]},{\"name\":\"example.com\",\"type\":\"NS\",\"data\":{\"dname\":\"ns1.dn"
                                "simple.com\"},\"ttl\":3600,\"context\":[\"anycast\"]},{\"name\":\"example.com\",\"type\":\"NS\",\"data\":{\""
                                "dname\":\"ns2.dnsimple.com\"},\"ttl\":3600,\"context\":[\"anycast\"]},{\"name\":\"example.com\",\"type\":\"N"
                                "S\",\"data\":{\"dname\":\"ns3.dnsimple.com\"},\"ttl\":3600,\"context\":[\"anycast\"]},{\"name\":\"example.co"
                                "m\",\"type\":\"NS\",\"data\":{\"dname\":\"ns4.dnsimple.com\"},\"ttl\":3600,\"context\":[\"anycast\"]},{\"nam"
                                "e\":\"*.qa.example.com\",\"type\":\"A\",\"data\":{\"ip\":\"5.4.3.2\"},\"ttl\":3600,\"context\":[]},{\"name\""
                                ":\"example.com\",\"type\":\"A\",\"data\":{\"ip\":\"1.2.3.4\"},\"ttl\":3600,\"context\":[]},{\"name\":\"examp"
                                "le.com\",\"type\":\"AAAA\",\"data\":{\"ip\":\"2001:db8:0:0:0:0:2:1\"},\"ttl\":3600,\"context\":[]},{\"name\""
                                ":\"www.example.com\",\"type\":\"CNAME\",\"data\":{\"dname\":\"example.com\"},\"ttl\":3600,\"context\":[]},{\""
                                "name\":\"example.com\",\"type\":\"CAA\",\"data\":{\"flags\":0,\"tag\":\"issue\",\"value\":\"comodoca.com\"},\""
                                "ttl\":3600,\"context\":[]},{\"name\":\"example.com\",\"type\":\"MX\",\"data\":{\"preference\":10,\"exchange\""
                                ":\"mailserver.foo.com\"},\"ttl\":3600,\"context\":[]},{\"name\":\"example.com\",\"type\":\"TXT\",\"data\":{\""
                                "txt\":\"this is a test\"},\"ttl\":3600,\"context\":[]},{\"name\":\"example.com\",\"type\":\"SPF\",\"data\":{\""
                                "spf\":\"v=spf1 a mx ~all\"},\"ttl\":3600,\"context\":[]},{\"name\":\"example.com\",\"type\":\"TXT\",\"data\""
                                ":{\"txt\":\"v=spf1 a mx ~all\"},\"ttl\":3600,\"context\":[]},{\"name\":\"example.com\",\"type\":\"SSHFP\",\""
                                "data\":{\"alg\":3,\"fptype\":2,\"fp\":\"ABC123\"},\"ttl\":3600,\"context\":[]},{\"name\":\"_foo._bar.example"
                                ".com\",\"type\":\"SRV\",\"data\":{\"priority\":20,\"weight\":10,\"port\":3333,\"target\":\"example.net\"},\""
                                "ttl\":3600,\"context\":[]},{\"name\":\"example.com\",\"type\":\"NAPTR\",\"data\":{\"order\":5,\"preference\""
                                ":10,\"flags\":\"u\",\"services\":\"foo\",\"regexp\":\"https:\/\/example\\\\.net\",\"replacement\":\"example."
                                "org\"},\"ttl\":3600,\"context\":[]},{\"name\":\"example.com\",\"type\":\"A\",\"data\":{\"ip\":\"5.5.5.5\"},\""
                                "ttl\":3600,\"context\":[\"SV1\"]},{\"name\":\"example.com\",\"type\":\"HINFO\",\"data\":{\"cpu\":\"cpu\",\"o"
                                "s\":\"os\"},\"ttl\":3600,\"context\":[]},{\"name\":\"example.com\",\"type\":\"DNSKEY\",\"data\":{\"flags\":2"
                                "57,\"protocol\":3,\"alg\":8,\"public_key\":\"AwEAAcFwY\/oPw5JPGTT2qf2opNMpNAopxC6xWvGO2QAKA7ERAzKYsiXt7j1\/t"
                                "tJjgnLS2Qj30bbnRyazj7Lg9oZcmiJ4\/cfBHLBczzaxtqwZrxX1rcQz1OpU\/hnq4W5Rsk2i1hxdpRjLnVfddVFD3GDDgIEjvaiKtaJcA61"
                                "WtDDA08Ba90S7czkUh2Nfv7cTYEFhjnx0bdtapwRQEirHjzyAJqs=\",\"key_tag\":0},\"ttl\":3600,\"context\":[]},{\"name\""
                                ":\"example.com\",\"type\":\"DNSKEY\",\"data\":{\"flags\":256,\"protocol\":3,\"alg\":8,\"public_key\":\"AwEAA"
                                "ddpSYg8TvfhxHRTG1zrCPXWuG\/gN0\/q2dzQtM3um6zVl0sIFQKWfcdcowpim13K4euSqzltBB+XwDjv9fbWb6xi0mTF0c0NgOQ\/Ctf5sQ"
                                "OBtGBkopbQgxDuXDTC1jJaUTVlzjN9m8KYoVacTbhMFBAtwn6LC1sEYfwiCsADk3cV\",\"key_tag\":0},\"ttl\":3600,\"context\""
                                ":[]},{\"name\":\"example.com\",\"type\":\"DNSKEY\",\"data\":{\"flags\":257,\"protocol\":3,\"alg\":8,\"public"
                                "_key\":\"AwEAAbPhmoznnzWMbx0h+RcyI+Bi2tzlOnd\/AbZK7iXgGY62lZo442+6TpZNlkeFEqk+YKxUce70RWkG\/LHuJeywfmPySSra2"
                                "rYG3P3ntAgbcrbwMDa9cmYVEnS2+ObEFeqowcoe4kjzy5249skMn9Hl8D5pWXp0EbzOSuKSRDFEaGfNycvc8\/VfcEi8LwUffTkq8ZFE9P6Q"
                                "EqyeDM4yO2XmoSs=\",\"key_tag\":0},\"ttl\":3600,\"context\":[]},{\"name\":\"example.com\",\"type\":\"DNSKEY\""
                                ",\"data\":{\"flags\":256,\"protocol\":3,\"alg\":8,\"public_key\":\"AwEAAdAKvoBtIj2GzLpawDNm\/ztuuxIbU2lticK5"
                                "lMwisLN8HY1QXjdFk+pOCHp1XsS2Odd6rQyy\/IJvBEFFeeZDoyUeoa2i93STTETMZZ\/dX1YtJPQnw8MJ0buxfeCxZGRVmbpu4p+YeZ2AFN"
                                "1ZSziKD7HununBWFXQc7vHRK0QSBTH\",\"key_tag\":0},\"ttl\":3600,\"context\":[]},{\"name\":\"example.com\",\"typ"
                                "e\":\"CDNSKEY\",\"data\":{\"flags\":257,\"protocol\":3,\"alg\":8,\"public_key\":\"AwEAAbPhmoznnzWMbx0h+RcyI+"
                                "Bi2tzlOnd\/AbZK7iXgGY62lZo442+6TpZNlkeFEqk+YKxUce70RWkG\/LHuJeywfmPySSra2rYG3P3ntAgbcrbwMDa9cmYVEnS2+ObEFeqo"
                                "wcoe4kjzy5249skMn9Hl8D5pWXp0EbzOSuKSRDFEaGfNycvc8\/VfcEi8LwUffTkq8ZFE9P6QEqyeDM4yO2XmoSs=\",\"key_tag\":0},\""
                                "ttl\":3600,\"context\":[]},{\"name\":\"example.com\",\"type\":\"CDS\",\"data\":{\"flags\":61079,\"alg\":8,\""
                                "digest_type\":2,\"digest\":\"933FE542B3351226B7D0460EBFCB3D48909106B052E803E04063ACC179D3664B\",\"keytag\":0"
                                "},\"ttl\":3600,\"context\":[]}],\"keys\":[{\"ksk\":\"-----BEGIN RSA PRIVATE KEY-----\\nMIIC7AIBAAKBoQDBcGP6D"
                                "8OSTxk09qn9qKTTKTQKKcQusVrxjtkACgOxEQMymLIl\\n7e49f7bSY4Jy0tkI99G250cms4+y4PaGXJoieP3HwRywXM82sbasGa8V9a3EM9"
                                "Tq\\nVP4Z6uFuUbJNotYcXaUYy51X3XVRQ9xgw4CBI72oirWiXAOtVrQwwNPAWvdEu3M5\\nFIdjX7+3E2BBYY58dG3bWqcEUBIqx488gCar"
                                "AgMBAAECgaBZk\/9oVJZ\/kYudwEB2\\nS\/uQIbuMnUzRRqZTyI\/q+bg97h\/p9VZCRE2YQyVZhmVpYQTKp2CBb9a+MFbyQkVH\\ncWibY"
                                "CY9s8riTQhUTrXGOtqesumWkTDdacbyuMjobme4WPX8L3xlX5spttpkZQfc\\neC0hpwX8bKRUuQifHPAhjuYxcVWIOZk5OaprHxwoXtM0oS"
                                "NPaGiPCM0fq4GmnF1n\\n3Eg5AlEA4aB6F0pG5ajnycvWETz\/WZpv\/wkcO0UlbgSFlx2OD545CKYcZlbx22bl\\nWvYHvkio1AAg03oFQf"
                                "XNtcl6274s2WFEJw5v0UBk0VHGq2zeTDUCUQDbeqkepngF\\njyuRSzfViuA3jpO\/8zmFm6Fpr5eCNgqEf+uC7zF+dg9bnnfEA88+x8Ijui"
                                "oRvbx7\\nkSMjiIijQUgo103vXadpPhBXFx7EadBDXwJQV0wtEQfXKJLSo\/xvJhpQvk2H2cif\\nmLsnQUsUmSSBS7+vV45V3K71QyurwCc"
                                "DVfdtAyHNkaVblWrSneyH0a\/iUHVW1jm6\\nv97HY0ndsYQc+qUCUQC3Al24wAh+YjZq7bR97FIwIUQUH4TMYsxCKveDzPoSJ\/RC\\ndp7"
                                "nmxwNQmMNYDvUVo8MaXQg3PwocQpC29tLfejknTtQJ+CrgePwKsgt8SmGswJQ\\nVt10NCsGdK7ACTz1Asfcb4JQUYM\/d14ofhJRHptROLE"
                                "93gHx9He+JGq4ET74YQvd\\nD8V0L923eLixsHh5I5t\/1QEVwbpeGcDhb+j8LeVvV8w=\\n-----END RSA PRIVATE KEY-----\\n\",\""
                                "ksk_keytag\":57949,\"ksk_alg\":8,\"zsk\":\"-----BEGIN RSA PRIVATE KEY-----\\nMIICXQIBAAKBgQDXaUmIPE734cR0Uxt"
                                "c6wj11rhv4DdP6tnc0LTN7pus1ZdLCBUC\\nln3HXKMKYptdyuHrkqs5bQQfl8A47\/X21m+sYtJkxdHNDYDkPwrX+bEDgbRgZKKW\\n0IMQ"
                                "7lw0wtYyWlE1Zc4zfZvCmKFWnE24TBQQLcJ+iwtbBGH8IgrAA5N3FQIDAQAB\\nAoGBAIozFGgBOTCzedSflQiSChefAIlWMmZlaAzRIY6VL"
                                "O8\/wWbz8nbMkjmbZ0a8\\naK1OAo+ec5fOJz0VoM9mtEj+3nlvQoJBw1ubBy4o3yr6X8dOwyEqtH8Riciv9XlE\\nDg6uQH8u52CErzYd7i"
                                "o9NVn+vQZEFdw1kwy9bHl6Zb+SwwWpAkEA69Dw7b2VC4aP\\na\/wr0\/xME2hXb7qf2YsH3GreJHTH1D7fdQozKdw4o8tUFjKvOTy827N2X"
                                "7PSp+cW\\nXYzk7Pp7nwJBAOnZPx2KK58IqBdmRpSfdQmstbC9k9SWby1NxH7xerepdRr+Fvnr\\nSVZo4JcIyWk1FVUHd9ZNIagIJZhE2tR"
                                "WkMsCQDPX05\/wtfu6sX1ECz6nkPITVmWx\\n2cKx1iCXPg81vVjkGaxZebYSPEGGSg43Rl6HA94pLjUMC5vuKfSXLR0MVHECQEWu\\n6ADc"
                                "cH02bihy4KtfDNgyL\/4Xr9qUbVK5rskJGkFqbKv7dUtJ0pO+Mtau1p3UJKQu\\n0oX4fAP\/UXybX\/4QQZsCQQCcym4PAXhtW5U1FmV\/d"
                                "GCMb8rufZt7bmHHPulrAIVv\\n5Zse+HIV\/u0c36RRHSRuW4MPICrHE7Uf5B7\/7TcWp3nZ\\n-----END RSA PRIVATE KEY-----\\n\""
                                ",\"zsk_keytag\":15271,\"zsk_alg\":8,\"inception\":\"2020-12-02T08:38:09.631363Z\",\"until\":\"2021-03-02T08:"
                                "38:09.630312Z\"},{\"ksk\":\"-----BEGIN RSA PRIVATE KEY-----\\nMIIC7QIBAAKBoQCz4ZqM5581jG8dIfkXMiPgYtrc5Tp3fw"
                                "G2Su4l4BmOtpWaOONv\\nuk6WTZZHhRKpPmCsVHHu9EVpBvyx7iXssH5j8kkq2tq2Btz957QIG3K28DA2vXJm\\nFRJ0tvjmxBXqqMHKHuJI"
                                "88uduPbJDJ\/R5fA+aVl6dBG8zkrikkQxRGhnzcnL3PP1\\nX3BIvC8FH305KvGRRPT+kBKsngzOMjtl5qErAgMBAAECgaEAmKofJfkqaSMP"
                                "5pS\/\\nuA0I39ZmU9WEgohbJqB\/b8u7RSD25RXlCR0At5WPtpFdHiBfocJlk9ziz9lrO4OX\\n0kKUcjTeHi3yM0yt4Bv28m6BNHpFvrdo"
                                "31jOpSkvYzcip2LdYENMTxAi4NSsDDQg\\nLjuxbKJskvHgwz73XXj9g6X0uiotTzuUnT0gWJvIDykeXnoru2U2YfYjsN4uSHJF\\nPWYlwQ"
                                "JRAOgxqQv1pe7VSQ4sLAnwW3NsGPMHCmAbmcbsjxnPj8Wjf4L0ervHxebt\\nnZOCaUlUxZm9X8GiONZAGMG2xPz6tuKYz9wE\/6j+9jtFe2"
                                "5alaCLAlEAxlLnapw5\\ne3oYElrw1MR1aNOwiSXJuhQ8wlM6EifuV9HA\/Aq3AApOoKmwL3n9EqfxuZbFmuRA\\nu4FB78tFckIyhqhxHNz"
                                "9KNZR5ZkwUdWvdeECUBLk\/6GWgsM1nfVGSOsiIP76e+lC\\n2GhLtq7GTzrFdiiaDmVEqbwgHI2XJmx7fz\/VYyMIkwM5xTBCFQGmcs83Q6"
                                "yazMdV\\nrMw+uyDFna60NlrTAlBnPVkCgnjZ8mD9jSG5YNvNygUoH+e3WjmW30RnlynXxXU0\\nv08sUjFEKZFx5Yr8XzjSZ85OJ2wbL9pn"
                                "PeXU6OjseFsJr3CKBad0Yh5pO1evgQJR\\nAMFyXCvulXFDKMqV3ePut7pMGGTUl53qoEOYGPsokl+C2Ho7sOgR2wzNLpchYZNr\\nS4eCZD"
                                "PgcC+1JAVOUoDK8IyPbnQaZ0K3kGWxPpzC29xj\\n-----END RSA PRIVATE KEY-----\\n\",\"ksk_keytag\":61079,\"ksk_alg\""
                                ":8,\"zsk\":\"-----BEGIN RSA PRIVATE KEY-----\\nMIICXQIBAAKBgQDQCr6AbSI9hsy6WsAzZv87brsSG1NpbYnCuZTMIrCzfB2NU"
                                "F43\\nRZPqTgh6dV7EtjnXeq0MsvyCbwRBRXnmQ6MlHqGtovd0k0xEzGWf3V9WLST0J8PD\\nCdG7sX3gsWRkVZm6buKfmHmdgBTdWUs4ig+"
                                "x7p7pwVhV0HO7x0StEEgUxwIDAQAB\\nAoGANs891TPrW25SLZ6PGHvALnZDzsdoOFRlgOnHq+hPyVmfp4VO7RzllUstrKWT\\nbBveLUjio"
                                "n\/dSrfY1SFqtiGHr1w7tzTW39kTEdca4lvUtSmt7\/\/wrEV0GLsgHwnZ\\nVVyCuH0PpRcSmYYVYrSsCEH9\/mXxs8Fq0tsn+wMls7O1WW"
                                "ECQQDruuKG\/X\/tYmps\\nm239lLH8VyDRqQmX3mdtz+uKI8J37a+emd7lOWmkqa6b2ep+sZPDEk8xR7ktSiDb\\nAhyf85jvAkEA4e5dBt"
                                "UG05ieO+XtzvZOdMiU4zdWSAtgIyqegXunnvulwddEFbw0\\njwRzW5MYo0eTRfgaS0obMw8uZ0hN7zPRqQJBAOH1+ZCWTNta\/FLxRqTNtT"
                                "MCvcXb\\nuANowFIl\/U0kbBQTtcVdD6lAuICL2oEwiTQ6uj5CPcEqVFoSdZ4ZzyCQG+cCQDBv\\ni54FWXtPgszQlFUEVPmQburvWB4F4kx"
                                "nvKeBvQPGa1jNL5mBSbtHdvuw411N4PLl\\nJ63wazhdDtOxmpOnhlECQQCfdp\/ZOAKUalTUuqZLgIGwobDAmcOzXN\/85WWlWLIx\\nDf1"
                                "j0nabGCBLJt6VB0oVHd9a7rC7oTcl3TjO3kP9Zhts\\n-----END RSA PRIVATE KEY-----\\n\",\"zsk_keytag\":49225,\"zsk_al"
                                "g\":8,\"inception\":\"2020-12-02T10:45:48.279746Z\",\"until\":\"2021-03-02T10:45:48.279414Z\"}]}">>),
                   []).

json_to_erlang_ensure_sorting_and_defaults_test() ->
    ?assertEqual({"foo.org", [], [], []}, json_to_erlang([{<<"name">>, "foo.org"}, {<<"records">>, []}], [])).

json_record_to_erlang_test() ->
    erldns_events:start_link(),
    ?assertEqual({}, json_record_to_erlang([])),
    Name = <<"example.com">>,
    ?assertEqual({}, json_record_to_erlang([Name, <<"SOA">>, 3600, null, null])).

json_record_soa_to_erlang_test() ->
    Name = <<"example.com">>,
    ?assertEqual(#dns_rr{name = Name,
                         type = ?DNS_TYPE_SOA,
                         data =
                             #dns_rrdata_soa{mname = <<"ns1.example.com">>,
                                             rname = <<"admin.example.com">>,
                                             serial = 12345,
                                             refresh = 555,
                                             retry = 666,
                                             expire = 777,
                                             minimum = 888},
                         ttl = 3600},
                 json_record_to_erlang([Name,
                                        <<"SOA">>,
                                        3600,
                                        [{<<"mname">>, <<"ns1.example.com">>},
                                         {<<"rname">>, <<"admin.example.com">>},
                                         {<<"serial">>, 12345},
                                         {<<"refresh">>, 555},
                                         {<<"retry">>, 666},
                                         {<<"expire">>, 777},
                                         {<<"minimum">>, 888}],
                                        undefined])).

json_record_ns_to_erlang_test() ->
    Name = <<"example.com">>,
    ?assertEqual(#dns_rr{name = Name,
                         type = ?DNS_TYPE_NS,
                         data = #dns_rrdata_ns{dname = <<"ns1.example.com">>},
                         ttl = 3600},
                 json_record_to_erlang([Name, <<"NS">>, 3600, [{<<"dname">>, <<"ns1.example.com">>}], undefined])).

json_record_a_to_erlang_test() ->
    Name = <<"example.com">>,
    ?assertEqual(#dns_rr{name = Name,
                         type = ?DNS_TYPE_A,
                         data = #dns_rrdata_a{ip = {1, 2, 3, 4}},
                         ttl = 3600},
                 json_record_to_erlang([Name, <<"A">>, 3600, [{<<"ip">>, <<"1.2.3.4">>}], undefined])).

json_record_aaaa_to_erlang_test() ->
    Name = <<"example.com">>,
    ?assertEqual(#dns_rr{name = Name,
                         type = ?DNS_TYPE_AAAA,
                         data = #dns_rrdata_aaaa{ip = {0, 0, 0, 0, 0, 0, 0, 1}},
                         ttl = 3600},
                 json_record_to_erlang([Name, <<"AAAA">>, 3600, [{<<"ip">>, <<"::1">>}], undefined])).

json_record_cds_to_erlang_test() ->
    Name = <<"example-dnssec.com">>,
    ?assertEqual(#dns_rr{name = Name,
                         type = ?DNS_TYPE_CDS,
                         data =
                             #dns_rrdata_cds{keytag = 0,
                                             digest_type = 2,
                                             alg = 8,
                                             digest = hex_to_bin(<<"4315A7AD09AE0BEBA6CC3104BBCD88000ED796887F1C4D520A3A608D715B72CA">>)},
                         ttl = 3600},
                 json_record_to_erlang([Name,
                                        <<"CDS">>,
                                        3600,
                                        [{<<"keytag">>, 0},
                                         {<<"digest_type">>, 2},
                                         {<<"alg">>, 8},
                                         {<<"digest">>, <<"4315A7AD09AE0BEBA6CC3104BBCD88000ED796887F1C4D520A3A608D715B72CA">>}],
                                        undefined])).

parse_json_keys_unsorted_proplists_test() ->
    ?assertEqual([{keyset,
                   [1025,
                    117942195211355436516708579275854541924575773884167758398377054474457061084450782563901956510831117716183526402173215071572529228555976594387632086643427143744605045813923857147839015187463121492324352653506190767692034127161982651669657643423469824721891177589201529187860925827553628207715191151413138514807,
                    105745246243156727959858716443424706369448913365414799968886354206854672328400262610952095642393948469436742208387497220268443279066285356333886719634448317208189715942402022382731037836531762881862458283240610274107136766709456566004076449761688996028612988763775001691587086168632010166111722279727494037097],
                   37440,
                   8,
                   [513,
                    9170529505818457214552347052832728824507861128011245996056627438339703762731346681703094163316286362641501571794424157931806097889892946273849538579240359,
                    5130491166023191463112131781994138738077497356216817935415696052248528225933414267440640871636073852185344964288812312263453467652493907737029964715172561],
                   49016,
                   8,
                   {{2016, 11, 14}, {11, 36, 59}},
                   {{2017, 2, 12}, {11, 36, 59}}}],
                 parse_json_keys([[{<<"ksk">>,
                                    <<"-----BEGIN RSA PRIVATE KEY-----\nMIICXAIBAAKBgQCn9Iv82vkFiv8ts8K9jzUzfp3UEZx+76r+X9A4GOFfYbx3USCh\nEW0fLYT/Q"
                                      "kAM8/SiTkEXzZPqhrV083mp5VLYNLxic2ii6DrwvyGpENVPJnDQMu+C\nfKMyb9IWcm9MkeHh8t/ovsCQAEJWIPTnzv8rlQcDU44c3qgTpHS"
                                      "U8htjdwICBAEC\ngYEAlpYTHWYrcd0HQXO3F9lPqwwfHUt7VBaSEUYrk3N3ZYCWvmV1qyKbB/kb1SBs\n4GfW1vP966HXCffnX92LDXYxi7I"
                                      "t3TJaKmo8aF/leN7w8WLNJXUayEoQKUfKLprj\nN14Jx/tgMu7I/BOoHId8b7e57pBKtDiSF6WWn3K7tNPbfmkCQQDST41m62mC4MAa\nDsU"
                                      "dyM0Vg/tjduGqnygryCDEXDabdg95a3wMk0SQCQzZFHGNYnsXcffTqGs/y+5w\nQWxyOGSNAkEAzHFkDJla30NiiKvhu7dY+0+dGrfMA7pNU"
                                      "h+LGdXe5QFdjwwxqPbF\n7NMGXKMdB8agSCxGZC3bxdvYNF9LULzhEwJABpDYNSoQx+UMvaEN5XTpLmCHuS1r\nsmhfKZPcDx8Z7mAYda3wZ"
                                      "EuHQq+cf6i5XhOO9P5QKpKeslHLAMHa7NaNgQJBAI03\nGGacYLwui32fbzb8BYRg82Kga/OW6btY+O6hNs6iSR2gBlQ9j3Tgrzo+N4R/NQS"
                                      "l\nc05wGO2RnBUwlu0XUckCQHfHsWHVrrADTpalbv+FTDyWd0ouHXBmDecVZh3e7/ue\ncdMoblzeasvgp8CjFa9U+uDozY+aL6TNIpG++nn"
                                      "4lNw=\n-----END RSA PRIVATE KEY-----\n">>},
                                   {<<"ksk_alg">>, 8},
                                   {<<"ksk_keytag">>, 37440},
                                   {<<"zsk">>,
                                    <<"-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK8YnU+YqBxD/EDwVeHZsJillAJ80PCnLU+/rlGrlzgw+eabF8jT\nCaEwnpE74"
                                      "YHCLegKAAn+efeZrT/EBBrzlacCAgIBAkBh9VGFW2SJk1I9SBQaDIA9\nchdrrx+PHibSyozwT4eAPmd6OFoLausc7ls6v9evPeb+Yj3g0JX"
                                      "vTGp6BgNhFqLR\nAiEA1+ievAEBVM6IlOmpiTwlaWe/HV6MokBBq1G/tvJS0M8CIQDPm/DUsoTEv/Jj\n6O3U9hNcPLbvKMMGld2wbf7nrQm"
                                      "zqQIhAJrhwTaFdjnXhmfUB9a33vRIbSaIsLxA\nDyuM+03XP+YhAiEAmJIJz7WX9uPkCIy8wO655Hh4dt4UkBFRE98OqkHIwGkCIFFv\nN8r"
                                      "JojI+oEiJyNjEjWZD4qoUMUp3+YBl0htAJUE2\n-----END RSA PRIVATE KEY-----\n">>},
                                   {<<"zsk_alg">>, 8},
                                   {<<"zsk_keytag">>, 49016},
                                   {<<"inception">>, <<"2016-11-14T11:36:58.851612Z">>},
                                   {<<"until">>, <<"2017-02-12T11:36:58.849384Z">>}]])).

hex_to_bin_test() ->
    ?assertEqual(<<"">>, hex_to_bin(<<"">>)),
    ?assertEqual(<<255, 0, 255>>, hex_to_bin(<<"FF00FF">>)).

base64_to_bin_test() ->
    ?assertEqual(<<"">>, base64_to_bin(<<"">>)),
    ?assertEqual(<<3, 1, 0, 1, 191, 165, 76, 56, 217, 9, 250, 187, 15, 147, 125, 112, 215, 117, 186, 13, 244, 192, 186, 219, 9, 112, 125, 153, 82, 73, 64,
                   105, 80, 64, 122, 98, 28, 121, 76, 104, 177, 134, 177, 93, 191, 143, 159, 158, 162, 49, 233, 249, 100, 20, 204, 218, 78, 206, 181, 11, 23,
                   169, 172, 108, 75, 212, 185, 93, 160, 72, 73, 233, 110, 231, 145, 87, 139, 112, 59, 201, 174, 24, 79, 177, 121, 75, 172, 121, 42, 7, 135,
                   246, 147, 164, 15, 25, 245, 35, 238, 109, 189, 53, 153, 219, 170, 169, 165, 4, 55, 146, 110, 207, 100, 56, 132, 93, 29, 73, 68, 137, 98, 82,
                   79, 42, 26, 122, 54, 179, 160, 161, 236, 163>>,
                 base64_to_bin(<<"AwEAAb+lTDjZCfq7D5N9cNd1ug30wLrbCXB9mVJJQGlQQHpiHHlMaLGGsV2/j5+eojHp+WQUzNpOzrULF6msbEvUuV2gSEnpbueRV4twO8mu"
                                 "GE+xeUuseSoHh/aTpA8Z9SPubb01mduqqaUEN5Juz2Q4hF0dSUSJYlJPKhp6NrOgoeyj">>)).

-endif.
