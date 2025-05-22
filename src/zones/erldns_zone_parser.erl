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

-behaviour(gen_server).

-include_lib("dns_erlang/include/dns.hrl").
-include_lib("kernel/include/logger.hrl").

-include("erldns.hrl").

-export([
    start_link/0,
    zone_to_erlang/1,
    zone_to_erlang/2,
    register_parsers/1,
    register_parser/1,
    list_parsers/0
]).
% Gen server hooks
-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3
]).

-define(SERVER, ?MODULE).
-define(PARSE_TIMEOUT, 30 * 1000).

-ifdef(TEST).
-export([json_to_erlang/2, json_record_to_erlang/1, parse_json_keys_as_maps/1]).
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
-spec zone_to_erlang(map()) -> {binary(), binary(), [dns:rr()], [erldns:keyset()]}.
zone_to_erlang(Zone) ->
    gen_server:call(?SERVER, {parse_zone, Zone}, ?PARSE_TIMEOUT).

-spec zone_to_erlang(binary(), integer()) -> {binary(), binary(), [dns:rr()], [erldns:keyset()]}.
zone_to_erlang(Zone, Timeout) ->
    gen_server:call(?SERVER, {parse_zone, Zone}, Timeout).

%% @doc Register a list of custom parser modules.
-spec register_parsers([module()]) -> ok.
register_parsers(Modules) ->
    ?LOG_INFO("Registering custom parsers (modules: ~p)", [Modules]),
    gen_server:call(?SERVER, {register_parsers, Modules}).

%% @doc Register a custom parser module.
-spec register_parser(module()) -> ok.
register_parser(Module) ->
    ?LOG_INFO("Registering custom parser (module: ~p)", [Module]),
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
json_to_erlang(#{<<"name">> := Name, <<"records">> := JsonRecords} = Zone, Parsers) when is_map(Zone) ->
    Sha = maps:get(<<"sha">>, Zone, <<"">>),
    JsonKeys = maps:get(<<"keys">>, Zone, []),
    Records =
        lists:map(
            fun(JsonRecord) ->
                maybe
                    Data = json_record_to_list(JsonRecord),
                    % Filter by context
                    pass ?= apply_context_options(Data),
                    {} ?= json_record_to_erlang(Data),
                    {} ?= try_custom_parsers(Data, Parsers),
                    ?LOG_WARNING(
                        "Unsupported record (module: ~p, event: ~p, data: ~p)",
                        [?MODULE, unsupported_record, Data]
                    ),
                    {}
                else
                    fail ->
                        {};
                    Value ->
                        Value
                end
            end,
            JsonRecords
        ),
    FilteredRecords = lists:filter(record_filter(), Records),
    DistinctRecords = lists:usort(FilteredRecords),
    {Name, Sha, DistinctRecords, parse_json_keys_as_maps(JsonKeys)}.

parse_json_keys_as_maps([]) ->
    [];
parse_json_keys_as_maps(JsonKeys) ->
    parse_json_keys_as_maps(JsonKeys, []).

parse_json_keys_as_maps([], Keys) ->
    Keys;
parse_json_keys_as_maps([Key | Rest], Keys) ->
    KeySet =
        #keyset{
            key_signing_key = to_crypto_key(maps:get(<<"ksk">>, Key)),
            key_signing_key_tag = maps:get(<<"ksk_keytag">>, Key),
            key_signing_alg = maps:get(<<"ksk_alg">>, Key),
            zone_signing_key = to_crypto_key(maps:get(<<"zsk">>, Key)),
            zone_signing_key_tag = maps:get(<<"zsk_keytag">>, Key),
            zone_signing_alg = maps:get(<<"zsk_alg">>, Key),
            inception = iso8601:parse(maps:get(<<"inception">>, Key)),
            valid_until = iso8601:parse(maps:get(<<"until">>, Key))
        },
    parse_json_keys_as_maps(Rest, [KeySet | Keys]).

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
                lists:append([
                    apply_context_match_empty_check(erldns_config:keyget(match_empty, ContextOptions), Context),
                    apply_context_list_check(sets:from_list(erldns_config:keyget(allow, ContextOptions)), ContextSet)
                ]),
            case lists:any(fun(I) -> I =:= pass end, Result) of
                true ->
                    pass;
                _ ->
                    fail
            end;
        _ ->
            pass
    end.

%% TODO: We should just be passing the map and matching on its entries instead of constructing
%% this list, but this might break how custom parsers work. Investigate existing custom parsers.
json_record_to_list(JsonRecord) when is_map(JsonRecord) ->
    [
        maps:get(<<"name">>, JsonRecord),
        maps:get(<<"type">>, JsonRecord),
        maps:get(<<"ttl">>, JsonRecord),
        maps:get(<<"data">>, JsonRecord),
        maps:get(<<"context">>, JsonRecord, [])
    ].

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
    ?LOG_ERROR(
        "Error parsing record (module: ~p, event: ~p, name: ~p, type: ~p, data: ~p, reason:~p)",
        [?MODULE, error, Name, Type, Data, null_data]
    ),
    {};
json_record_to_erlang([Name, <<"SOA">>, Ttl, Data, _]) when is_map(Data) ->
    #dns_rr{
        name = Name,
        type = ?DNS_TYPE_SOA,
        data =
            #dns_rrdata_soa{
                mname = maps:get(<<"mname">>, Data),
                rname = maps:get(<<"rname">>, Data),
                serial = maps:get(<<"serial">>, Data),
                refresh = maps:get(<<"refresh">>, Data),
                retry = maps:get(<<"retry">>, Data),
                expire = maps:get(<<"expire">>, Data),
                minimum = maps:get(<<"minimum">>, Data)
            },
        ttl = Ttl
    };
json_record_to_erlang([Name, <<"SOA">>, Ttl, Data, _Context]) ->
    #dns_rr{
        name = Name,
        type = ?DNS_TYPE_SOA,
        data =
            #dns_rrdata_soa{
                mname = erldns_config:keyget(<<"mname">>, Data),
                rname = erldns_config:keyget(<<"rname">>, Data),
                serial = erldns_config:keyget(<<"serial">>, Data),
                refresh = erldns_config:keyget(<<"refresh">>, Data),
                retry = erldns_config:keyget(<<"retry">>, Data),
                expire = erldns_config:keyget(<<"expire">>, Data),
                minimum = erldns_config:keyget(<<"minimum">>, Data)
            },
        ttl = Ttl
    };
json_record_to_erlang([Name, <<"NS">>, Ttl, Data, _Context]) when is_map(Data) ->
    #dns_rr{
        name = Name,
        type = ?DNS_TYPE_NS,
        data = #dns_rrdata_ns{dname = maps:get(<<"dname">>, Data)},
        ttl = Ttl
    };
json_record_to_erlang([Name, <<"NS">>, Ttl, Data, _Context]) ->
    #dns_rr{
        name = Name,
        type = ?DNS_TYPE_NS,
        data = #dns_rrdata_ns{dname = erldns_config:keyget(<<"dname">>, Data)},
        ttl = Ttl
    };
json_record_to_erlang([Name, Type = <<"A">>, Ttl, Data, _Context]) when is_map(Data) ->
    case inet_parse:address(binary_to_list(maps:get(<<"ip">>, Data))) of
        {ok, Address} ->
            #dns_rr{
                name = Name,
                type = ?DNS_TYPE_A,
                data = #dns_rrdata_a{ip = Address},
                ttl = Ttl
            };
        {error, Reason} ->
            ?LOG_ERROR(
                "Error parsing record (module: ~p, event: ~p, name: ~p, type: ~p, data: ~p, reason:~p)",
                [?MODULE, error, Name, Type, Data, Reason]
            ),
            {}
    end;
json_record_to_erlang([Name, Type = <<"A">>, Ttl, Data, _Context]) ->
    case inet_parse:address(binary_to_list(erldns_config:keyget(<<"ip">>, Data))) of
        {ok, Address} ->
            #dns_rr{
                name = Name,
                type = ?DNS_TYPE_A,
                data = #dns_rrdata_a{ip = Address},
                ttl = Ttl
            };
        {error, Reason} ->
            ?LOG_ERROR(
                "Error parsing record (module: ~p, event: ~p, name: ~p, type: ~p, data: ~p, reason:~p)",
                [?MODULE, error, Name, Type, Data, Reason]
            ),
            {}
    end;
json_record_to_erlang([Name, Type = <<"AAAA">>, Ttl, Data, _Context]) when is_map(Data) ->
    case inet_parse:address(binary_to_list(maps:get(<<"ip">>, Data))) of
        {ok, Address} ->
            #dns_rr{
                name = Name,
                type = ?DNS_TYPE_AAAA,
                data = #dns_rrdata_aaaa{ip = Address},
                ttl = Ttl
            };
        {error, Reason} ->
            ?LOG_ERROR(
                "Error parsing record (module: ~p, event: ~p, name: ~p, type: ~p, data: ~p, reason:~p)",
                [?MODULE, error, Name, Type, Data, Reason]
            ),
            {}
    end;
json_record_to_erlang([Name, Type = <<"AAAA">>, Ttl, Data, _Context]) ->
    case inet_parse:address(binary_to_list(erldns_config:keyget(<<"ip">>, Data))) of
        {ok, Address} ->
            #dns_rr{
                name = Name,
                type = ?DNS_TYPE_AAAA,
                data = #dns_rrdata_aaaa{ip = Address},
                ttl = Ttl
            };
        {error, Reason} ->
            ?LOG_ERROR(
                "Error parsing record (module: ~p, event: ~p, name: ~p, type: ~p, data: ~p, reason:~p)",
                [?MODULE, error, Name, Type, Data, Reason]
            ),
            {}
    end;
json_record_to_erlang([Name, <<"CAA">>, Ttl, Data, _Context]) when is_map(Data) ->
    #dns_rr{
        name = Name,
        type = ?DNS_TYPE_CAA,
        data =
            #dns_rrdata_caa{
                flags = maps:get(<<"flags">>, Data),
                tag = maps:get(<<"tag">>, Data),
                value = maps:get(<<"value">>, Data)
            },
        ttl = Ttl
    };
json_record_to_erlang([Name, <<"CAA">>, Ttl, Data, _Context]) ->
    #dns_rr{
        name = Name,
        type = ?DNS_TYPE_CAA,
        data =
            #dns_rrdata_caa{
                flags = erldns_config:keyget(<<"flags">>, Data),
                tag = erldns_config:keyget(<<"tag">>, Data),
                value = erldns_config:keyget(<<"value">>, Data)
            },
        ttl = Ttl
    };
json_record_to_erlang([Name, <<"CNAME">>, Ttl, Data, _Context]) when is_map(Data) ->
    #dns_rr{
        name = Name,
        type = ?DNS_TYPE_CNAME,
        data = #dns_rrdata_cname{dname = maps:get(<<"dname">>, Data)},
        ttl = Ttl
    };
json_record_to_erlang([Name, <<"CNAME">>, Ttl, Data, _Context]) ->
    #dns_rr{
        name = Name,
        type = ?DNS_TYPE_CNAME,
        data = #dns_rrdata_cname{dname = erldns_config:keyget(<<"dname">>, Data)},
        ttl = Ttl
    };
json_record_to_erlang([Name, <<"MX">>, Ttl, Data, _Context]) when is_map(Data) ->
    #dns_rr{
        name = Name,
        type = ?DNS_TYPE_MX,
        data = #dns_rrdata_mx{exchange = maps:get(<<"exchange">>, Data), preference = maps:get(<<"preference">>, Data)},
        ttl = Ttl
    };
json_record_to_erlang([Name, <<"MX">>, Ttl, Data, _Context]) ->
    #dns_rr{
        name = Name,
        type = ?DNS_TYPE_MX,
        data = #dns_rrdata_mx{
            exchange = erldns_config:keyget(<<"exchange">>, Data), preference = erldns_config:keyget(<<"preference">>, Data)
        },
        ttl = Ttl
    };
json_record_to_erlang([Name, <<"HINFO">>, Ttl, Data, _Context]) when is_map(Data) ->
    #dns_rr{
        name = Name,
        type = ?DNS_TYPE_HINFO,
        data = #dns_rrdata_hinfo{cpu = maps:get(<<"cpu">>, Data), os = maps:get(<<"os">>, Data)},
        ttl = Ttl
    };
json_record_to_erlang([Name, <<"HINFO">>, Ttl, Data, _Context]) ->
    #dns_rr{
        name = Name,
        type = ?DNS_TYPE_HINFO,
        data = #dns_rrdata_hinfo{cpu = erldns_config:keyget(<<"cpu">>, Data), os = erldns_config:keyget(<<"os">>, Data)},
        ttl = Ttl
    };
json_record_to_erlang([Name, <<"RP">>, Ttl, Data, _Context]) when is_map(Data) ->
    #dns_rr{
        name = Name,
        type = ?DNS_TYPE_RP,
        data = #dns_rrdata_rp{mbox = maps:get(<<"mbox">>, Data), txt = maps:get(<<"txt">>, Data)},
        ttl = Ttl
    };
json_record_to_erlang([Name, <<"RP">>, Ttl, Data, _Context]) ->
    #dns_rr{
        name = Name,
        type = ?DNS_TYPE_RP,
        data = #dns_rrdata_rp{mbox = erldns_config:keyget(<<"mbox">>, Data), txt = erldns_config:keyget(<<"txt">>, Data)},
        ttl = Ttl
    };
json_record_to_erlang([_Name, Type, _Ttl, _Data, _Context | _] = Input) when
    Type =:= <<"TXT">> orelse Type =:= <<"SPF">>
->
    FfUseTxtsField = application:get_env(erldns, ff_use_txts_field, false),
    json_record_to_erlang_txt(Input, FfUseTxtsField);
json_record_to_erlang([Name, <<"PTR">>, Ttl, Data, _Context]) when is_map(Data) ->
    #dns_rr{
        name = Name,
        type = ?DNS_TYPE_PTR,
        data = #dns_rrdata_ptr{dname = maps:get(<<"dname">>, Data)},
        ttl = Ttl
    };
json_record_to_erlang([Name, <<"PTR">>, Ttl, Data, _Context]) ->
    #dns_rr{
        name = Name,
        type = ?DNS_TYPE_PTR,
        data = #dns_rrdata_ptr{dname = erldns_config:keyget(<<"dname">>, Data)},
        ttl = Ttl
    };
json_record_to_erlang([Name, Type = <<"SSHFP">>, Ttl, Data, _Context]) when is_map(Data) ->
    %% This function call may crash. Handle it as a bad record.
    try binary:decode_hex(maps:get(<<"fp">>, Data)) of
        Fp ->
            #dns_rr{
                name = Name,
                type = ?DNS_TYPE_SSHFP,
                data =
                    #dns_rrdata_sshfp{
                        alg = maps:get(<<"alg">>, Data),
                        fp_type = maps:get(<<"fptype">>, Data),
                        fp = Fp
                    },
                ttl = Ttl
            }
    catch
        Exception:Reason ->
            ?LOG_ERROR(
                "Error parsing record (module: ~p, event: ~p, name: ~p, type: ~p, data: ~p, exception: ~p, reason: ~p)",
                [?MODULE, error, Name, Type, Data, Exception, Reason]
            ),
            {}
    end;
json_record_to_erlang([Name, Type = <<"SSHFP">>, Ttl, Data, _Context]) ->
    %% This function call may crash. Handle it as a bad record.
    try binary:decode_hex(erldns_config:keyget(<<"fp">>, Data)) of
        Fp ->
            #dns_rr{
                name = Name,
                type = ?DNS_TYPE_SSHFP,
                data =
                    #dns_rrdata_sshfp{
                        alg = erldns_config:keyget(<<"alg">>, Data),
                        fp_type = erldns_config:keyget(<<"fptype">>, Data),
                        fp = Fp
                    },
                ttl = Ttl
            }
    catch
        Exception:Reason ->
            ?LOG_ERROR(
                "Error parsing record (module: ~p, event: ~p, name: ~p, type: ~p, data: ~p, exception: ~p, reason: ~p)",
                [?MODULE, error, Name, Type, Data, Exception, Reason]
            ),
            {}
    end;
json_record_to_erlang([Name, <<"SRV">>, Ttl, Data, _Context]) when is_map(Data) ->
    #dns_rr{
        name = Name,
        type = ?DNS_TYPE_SRV,
        data =
            #dns_rrdata_srv{
                priority = maps:get(<<"priority">>, Data),
                weight = maps:get(<<"weight">>, Data),
                port = maps:get(<<"port">>, Data),
                target = maps:get(<<"target">>, Data)
            },
        ttl = Ttl
    };
json_record_to_erlang([Name, <<"SRV">>, Ttl, Data, _Context]) ->
    #dns_rr{
        name = Name,
        type = ?DNS_TYPE_SRV,
        data =
            #dns_rrdata_srv{
                priority = erldns_config:keyget(<<"priority">>, Data),
                weight = erldns_config:keyget(<<"weight">>, Data),
                port = erldns_config:keyget(<<"port">>, Data),
                target = erldns_config:keyget(<<"target">>, Data)
            },
        ttl = Ttl
    };
json_record_to_erlang([Name, <<"NAPTR">>, Ttl, Data, _Context]) when is_map(Data) ->
    #dns_rr{
        name = Name,
        type = ?DNS_TYPE_NAPTR,
        data =
            #dns_rrdata_naptr{
                order = maps:get(<<"order">>, Data),
                preference = maps:get(<<"preference">>, Data),
                flags = maps:get(<<"flags">>, Data),
                services = maps:get(<<"services">>, Data),
                regexp = maps:get(<<"regexp">>, Data),
                replacement = maps:get(<<"replacement">>, Data)
            },
        ttl = Ttl
    };
json_record_to_erlang([Name, <<"NAPTR">>, Ttl, Data, _Context]) ->
    #dns_rr{
        name = Name,
        type = ?DNS_TYPE_NAPTR,
        data =
            #dns_rrdata_naptr{
                order = erldns_config:keyget(<<"order">>, Data),
                preference = erldns_config:keyget(<<"preference">>, Data),
                flags = erldns_config:keyget(<<"flags">>, Data),
                services = erldns_config:keyget(<<"services">>, Data),
                regexp = erldns_config:keyget(<<"regexp">>, Data),
                replacement = erldns_config:keyget(<<"replacement">>, Data)
            },
        ttl = Ttl
    };
json_record_to_erlang([Name, Type = <<"DS">>, Ttl, Data, _Context]) when is_map(Data) ->
    try binary:decode_hex(maps:get(<<"digest">>, Data)) of
        Digest ->
            #dns_rr{
                name = Name,
                type = ?DNS_TYPE_DS,
                data =
                    #dns_rrdata_ds{
                        keytag = maps:get(<<"keytag">>, Data),
                        alg = maps:get(<<"alg">>, Data),
                        digest_type = maps:get(<<"digest_type">>, Data),
                        digest = Digest
                    },
                ttl = Ttl
            }
    catch
        Exception:Reason ->
            ?LOG_ERROR(
                "Error parsing record (module: ~p, event: ~p, name: ~p, type: ~p, data: ~p, exception: ~p, reason: ~p)",
                [?MODULE, error, Name, Type, Data, Exception, Reason]
            ),
            {}
    end;
json_record_to_erlang([Name, Type = <<"DS">>, Ttl, Data, _Context]) ->
    try binary:decode_hex(erldns_config:keyget(<<"digest">>, Data)) of
        Digest ->
            #dns_rr{
                name = Name,
                type = ?DNS_TYPE_DS,
                data =
                    #dns_rrdata_ds{
                        keytag = erldns_config:keyget(<<"keytag">>, Data),
                        alg = erldns_config:keyget(<<"alg">>, Data),
                        digest_type = erldns_config:keyget(<<"digest_type">>, Data),
                        digest = Digest
                    },
                ttl = Ttl
            }
    catch
        Exception:Reason ->
            ?LOG_ERROR(
                "Error parsing record (module: ~p, event: ~p, name: ~p, type: ~p, data: ~p, exception: ~p, reason: ~p)",
                [?MODULE, error, Name, Type, Data, Exception, Reason]
            ),
            {}
    end;
json_record_to_erlang([Name, Type = <<"CDS">>, Ttl, Data, _Context]) when is_map(Data) ->
    try binary:decode_hex(maps:get(<<"digest">>, Data)) of
        Digest ->
            #dns_rr{
                name = Name,
                type = ?DNS_TYPE_CDS,
                data =
                    #dns_rrdata_cds{
                        keytag = maps:get(<<"keytag">>, Data),
                        alg = maps:get(<<"alg">>, Data),
                        digest_type = maps:get(<<"digest_type">>, Data),
                        digest = Digest
                    },
                ttl = Ttl
            }
    catch
        Exception:Reason ->
            ?LOG_ERROR(
                "Error parsing record (module: ~p, event: ~p, name: ~p, type: ~p, data: ~p, exception: ~p, reason: ~p)",
                [?MODULE, error, Name, Type, Data, Exception, Reason]
            ),
            {}
    end;
json_record_to_erlang([Name, Type = <<"CDS">>, Ttl, Data, _Context]) ->
    try binary:decode_hex(erldns_config:keyget(<<"digest">>, Data)) of
        Digest ->
            #dns_rr{
                name = Name,
                type = ?DNS_TYPE_CDS,
                data =
                    #dns_rrdata_cds{
                        keytag = erldns_config:keyget(<<"keytag">>, Data),
                        alg = erldns_config:keyget(<<"alg">>, Data),
                        digest_type = erldns_config:keyget(<<"digest_type">>, Data),
                        digest = Digest
                    },
                ttl = Ttl
            }
    catch
        Exception:Reason ->
            ?LOG_ERROR(
                "Error parsing record (module: ~p, event: ~p, name: ~p, type: ~p, data: ~p, exception: ~p, reason: ~p)",
                [?MODULE, error, Name, Type, Data, Exception, Reason]
            ),
            {}
    end;
json_record_to_erlang([Name, Type = <<"DNSKEY">>, Ttl, Data, _Context]) when is_map(Data) ->
    try base64:decode(maps:get(<<"public_key">>, Data)) of
        PublicKey ->
            dnssec:add_keytag_to_dnskey(#dns_rr{
                name = Name,
                type = ?DNS_TYPE_DNSKEY,
                data =
                    #dns_rrdata_dnskey{
                        flags = maps:get(<<"flags">>, Data),
                        protocol = maps:get(<<"protocol">>, Data),
                        alg = maps:get(<<"alg">>, Data),
                        public_key = PublicKey,
                        key_tag = 0
                    },
                ttl = Ttl
            })
    catch
        Exception:Reason ->
            ?LOG_ERROR(
                "Error parsing record (module: ~p, event: ~p, name: ~p, type: ~p, data: ~p, exception: ~p, reason: ~p)",
                [?MODULE, error, Name, Type, Data, Exception, Reason]
            ),
            {}
    end;
json_record_to_erlang([Name, Type = <<"DNSKEY">>, Ttl, Data, _Context]) ->
    try base64:decode(erldns_config:keyget(<<"public_key">>, Data)) of
        PublicKey ->
            dnssec:add_keytag_to_dnskey(#dns_rr{
                name = Name,
                type = ?DNS_TYPE_DNSKEY,
                data =
                    #dns_rrdata_dnskey{
                        flags = erldns_config:keyget(<<"flags">>, Data),
                        protocol = erldns_config:keyget(<<"protocol">>, Data),
                        alg = erldns_config:keyget(<<"alg">>, Data),
                        public_key = PublicKey,
                        key_tag = 0
                    },
                ttl = Ttl
            })
    catch
        Exception:Reason ->
            ?LOG_ERROR(
                "Error parsing record (module: ~p, event: ~p, name: ~p, type: ~p, data: ~p, exception: ~p, reason: ~p)",
                [?MODULE, error, Name, Type, Data, Exception, Reason]
            ),
            {}
    end;
json_record_to_erlang([Name, Type = <<"CDNSKEY">>, Ttl, Data, _Context]) when is_map(Data) ->
    try base64:decode(maps:get(<<"public_key">>, Data)) of
        PublicKey ->
            dnssec:add_keytag_to_cdnskey(#dns_rr{
                name = Name,
                type = ?DNS_TYPE_CDNSKEY,
                data =
                    #dns_rrdata_cdnskey{
                        flags = maps:get(<<"flags">>, Data),
                        protocol = maps:get(<<"protocol">>, Data),
                        alg = maps:get(<<"alg">>, Data),
                        public_key = PublicKey,
                        key_tag = 0
                    },
                ttl = Ttl
            })
    catch
        Exception:Reason ->
            ?LOG_ERROR(
                "Error parsing record (module: ~p, event: ~p, name: ~p, type: ~p, data: ~p, exception: ~p, reason: ~p)",
                [?MODULE, error, Name, Type, Data, Exception, Reason]
            ),
            {}
    end;
json_record_to_erlang([Name, Type = <<"CDNSKEY">>, Ttl, Data, _Context]) ->
    try base64:decode(erldns_config:keyget(<<"public_key">>, Data)) of
        PublicKey ->
            dnssec:add_keytag_to_cdnskey(#dns_rr{
                name = Name,
                type = ?DNS_TYPE_CDNSKEY,
                data =
                    #dns_rrdata_cdnskey{
                        flags = erldns_config:keyget(<<"flags">>, Data),
                        protocol = erldns_config:keyget(<<"protocol">>, Data),
                        alg = erldns_config:keyget(<<"alg">>, Data),
                        public_key = PublicKey,
                        key_tag = 0
                    },
                ttl = Ttl
            })
    catch
        Exception:Reason ->
            ?LOG_ERROR(
                "Error parsing record (module: ~p, event: ~p, name: ~p, type: ~p, data: ~p, exception: ~p, reason: ~p)",
                [?MODULE, error, Name, Type, Data, Exception, Reason]
            ),
            {}
    end;
json_record_to_erlang(_Data) ->
    {}.

json_record_to_erlang_txt(Input, true) ->
    json_record_to_erlang_txts(Input);
json_record_to_erlang_txt(Input, false) ->
    json_record_to_erlang_txt(Input).

json_record_to_erlang_txts([Name, Type, Ttl, #{<<"txts">> := Txts} = Data, Context]) when is_list(Txts) ->
    json_record_to_erlang_txts([Name, Type, Ttl, Data, Context, Txts]);
json_record_to_erlang_txts([Name, Type, Ttl, Data, Context]) when is_list(Data) ->
    Txts =
        case erldns_config:keyget(<<"txts">>, Data) of
            Value when is_list(Value) -> Value;
            _ -> erldns_config:keyget(<<"txt">>, Data)
        end,
    json_record_to_erlang_txts([Name, Type, Ttl, Data, Context, Txts]);
json_record_to_erlang_txts([Name, Type, Ttl, _Data, _Context, Txts]) when is_list(Txts) ->
    txt_or_spf_record(Type, Name, Ttl, Txts);
json_record_to_erlang_txts(Input) ->
    json_record_to_erlang_txt(Input).

json_record_to_erlang_txt([Name, <<"TXT">> = Type, Ttl, #{<<"txt">> := Txt} = Data, Context]) ->
    json_record_to_erlang_txt([Name, Type, Ttl, Data, Context, Txt]);
json_record_to_erlang_txt([Name, <<"SPF">> = Type, Ttl, #{<<"spf">> := Txt} = Data, Context]) ->
    json_record_to_erlang_txt([Name, Type, Ttl, Data, Context, Txt]);
json_record_to_erlang_txt([Name, <<"TXT">> = Type, Ttl, Data, Context]) ->
    Txts = erldns_config:keyget(<<"txt">>, Data),
    json_record_to_erlang_txt([Name, Type, Ttl, Data, Context, Txts]);
json_record_to_erlang_txt([Name, <<"SPF">> = Type, Ttl, Data, Context]) ->
    Txts = erldns_config:keyget(<<"spf">>, Data),
    json_record_to_erlang_txt([Name, Type, Ttl, Data, Context, Txts]);
json_record_to_erlang_txt([Name, Type, Ttl, Data, _Context, Value]) ->
    %% This function call may crash. Handle it as a bad record.
    try
        ParsedText = erldns_txt:parse(Value),
        txt_or_spf_record(Type, Name, Ttl, lists:flatten(ParsedText))
    catch
        Exception:Reason ->
            ?LOG_ERROR(
                "Error parsing record (module: ~p, event: ~p, name: ~p, type: ~p, data: ~p, exception: ~p, reason: ~p)",
                [?MODULE, error, Name, Type, Data, Exception, Reason]
            ),
            {}
    end.

txt_or_spf_record(<<"TXT">>, Name, Ttl, ParsedText) ->
    #dns_rr{name = Name, type = ?DNS_TYPE_TXT, data = #dns_rrdata_txt{txt = ParsedText}, ttl = Ttl};
txt_or_spf_record(<<"SPF">>, Name, Ttl, ParsedText) ->
    #dns_rr{name = Name, type = ?DNS_TYPE_SPF, data = #dns_rrdata_spf{spf = ParsedText}, ttl = Ttl}.
