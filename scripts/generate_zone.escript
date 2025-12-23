#!/usr/bin/env escript
%% -*- erlang -*-
%% Zone generator script for erldns
%% Generates JSON zone files with configurable parameters

-module(generate_zone).

-export([main/1]).

-include("../_build/default/lib/dns_erlang/include/dns.hrl").
-include("../_build/default/lib/erldns/include/erldns.hrl").
-include_lib("public_key/include/public_key.hrl").

% DNS and DNSSEC constants
% These match the definitions in dns_erlang/include/dns.hrl and erldns/include/erldns.hrl
% Using local definitions for portability in escript context

-define(DEFAULT_TTL, 3600).
-define(DEFAULT_SOA_REFRESH, 86400).
-define(DEFAULT_SOA_RETRY, 7200).
-define(DEFAULT_SOA_EXPIRE, 604800).
-define(DEFAULT_SOA_MINIMUM, 300).

% DNSSEC constants (RFC 4034)

% DNSKEY protocol is always 3
-define(DNSKEY_PROTOCOL, 3).
% SHA-256 digest type for DS/CDS records
-define(DS_DIGEST_TYPE_SHA256, 2).

-record(opts, {
    zone_name :: binary() | undefined,
    output_file :: string() | undefined,
    num_records = 10 :: non_neg_integer(),
    with_dnssec = true :: boolean(),
    % 8=RSA, 13=ECDSA P-256, 14=ECDSA P-384, 15=Ed25519, 16=Ed448
    dnssec_alg = 15 :: non_neg_integer(),
    randomize = true :: boolean(),
    % Number of zones to generate
    count = 1 :: non_neg_integer(),
    seed :: integer() | undefined,
    % Base name for multiple zones
    base_name :: binary() | undefined,
    % Output file pattern (%d for index, %s for zone name)
    output_pattern :: string() | undefined,
    % Base directory where all generated files will be placed
    base_dir :: string() | undefined
}).

main(Args) ->
    Spec = create_spec(),
    % Handle --help before parsing
    case lists:member("--help", Args) orelse lists:member("-h", Args) of
        true ->
            io:format("~s~n", [argparse:help(Spec)]),
            halt(0);
        false ->
            ok
    end,
    case argparse:parse(Args, Spec) of
        {ok, ParsedArgs, _RemainingArgs, _ParsedSpec} ->
            Opts = args_to_opts(ParsedArgs),
            % Validate options
            case validate_opts(Opts) of
                ok ->
                    case Opts#opts.count of
                        1 -> generate_zone(Opts);
                        N when N > 1 -> generate_zones_parallel(Opts)
                    end;
                {error, Reason} ->
                    io:format(standard_error, "Error: ~s~n", [Reason]),
                    io:format(standard_error, "~s~n", [argparse:help(Spec)]),
                    halt(1)
            end;
        {error, {help, HelpText}} ->
            io:format("~s~n", [HelpText]),
            halt(0);
        {error, Reason} ->
            ErrorMsg =
                case Reason of
                    {_, _, Arg, _} when is_list(Arg) -> "Invalid argument: " ++ Arg;
                    {_, _, Arg, _} when is_binary(Arg) ->
                        "Invalid argument: " ++ binary_to_list(Arg);
                    {error, {_, _, Arg, _}} when is_list(Arg) -> "Invalid argument: " ++ Arg;
                    {error, {_, _, Arg, _}} when is_binary(Arg) ->
                        "Invalid argument: " ++ binary_to_list(Arg);
                    _ ->
                        io_lib:format("~p", [Reason])
                end,
            io:format(standard_error, "Error: ~s~n", [ErrorMsg]),
            io:format(standard_error, "~s~n", [argparse:help(Spec)]),
            halt(1)
    end.

create_spec() ->
    #{
        progname => generate_zone,
        arguments => [
            #{
                name => zone_name,
                long => "-zone-name",
                short => $z,
                type => string,
                help => "Zone name (required when --count is 1, ignored when --count > 1)"
            },
            #{
                name => output,
                long => "-output",
                short => $o,
                type => string,
                help => "Output file path (required when --count is 1, ignored when --count > 1)"
            },
            #{
                name => num_records,
                long => "-num-records",
                short => $n,
                type => integer,
                default => 10,
                help => "Number of records to generate (default: 10)"
            },
            #{
                name => with_dnssec,
                long => "-with-dnssec",
                type => boolean,
                default => false,
                help => "Generate DNSSEC records and keys"
            },
            #{
                name => dnssec_alg,
                long => "-dnssec-alg",
                short => $a,
                type => integer,
                default => 8,
                help =>
                    "DNSSEC algorithm: 8=RSA, 13=ECDSA-P256, 14=ECDSA-P384, 15=Ed25519, 16=Ed448 (default: 8)"
            },
            #{
                name => no_randomize,
                long => "-no-randomize",
                type => boolean,
                default => false,
                help => "Disable randomization (default: randomization is enabled)"
            },
            #{
                name => seed,
                long => "-seed",
                short => $s,
                type => integer,
                help => "Random seed for reproducible output"
            },
            #{
                name => count,
                long => "-count",
                short => $c,
                type => integer,
                default => 1,
                help =>
                    "Number of zones to generate (default: 1). When > 1, generates zones in parallel."
            },
            #{
                name => base_name,
                long => "-base-name",
                short => $b,
                type => string,
                help =>
                    "Base zone name for multiple zones (required when --count > 1). Zones will be named: base-name1, base-name2, etc."
            },
            #{
                name => output_pattern,
                long => "-output-pattern",
                short => $p,
                type => string,
                help =>
                    "Output file pattern for multiple zones. Use %%d for index, %%s for zone name. Default: output-%%d.json when --count > 1"
            },
            #{
                name => base_dir,
                long => "-base-dir",
                short => $d,
                type => string,
                help =>
                    "Base directory where all generated files will be placed. Directory will be created if it doesn't exist."
            }
        ],
        help =>
            "Zone generator script for erldns\n\nGenerates JSON zone files with configurable parameters for correctness and load testing."
    }.

validate_opts(Opts) ->
    case Opts#opts.count of
        1 ->
            % Single zone: zone_name and output_file are required
            case {Opts#opts.zone_name, Opts#opts.output_file} of
                {undefined, _} -> {error, "Zone name is required (use --zone-name)"};
                {_, undefined} -> {error, "Output file is required (use --output)"};
                _ -> ok
            end;
        N when N > 1 ->
            % Multiple zones: base_name is required
            case Opts#opts.base_name of
                undefined -> {error, "Base name is required when --count > 1 (use --base-name)"};
                _ -> ok
            end
    end.

args_to_opts(Args) ->
    % Randomization is enabled by default, unless --no-randomize is specified
    Randomize = not maps:get(no_randomize, Args, false),
    Count = maps:get(count, Args, 1),
    % Convert zone_name from string to binary (if provided)
    ZoneNameRaw = maps:get(zone_name, Args, undefined),
    ZoneName =
        case ZoneNameRaw of
            undefined -> undefined;
            ZBin when is_binary(ZBin) -> ZBin;
            ZStr when is_list(ZStr) -> list_to_binary(ZStr);
            _ -> undefined
        end,
    % Convert base_name from string to binary (if provided)
    BaseNameRaw = maps:get(base_name, Args, undefined),
    BaseName =
        case BaseNameRaw of
            undefined -> undefined;
            BBin when is_binary(BBin) -> BBin;
            BStr when is_list(BStr) -> list_to_binary(BStr);
            _ -> undefined
        end,
    #opts{
        zone_name = ZoneName,
        output_file = maps:get(output, Args, undefined),
        num_records = maps:get(num_records, Args, 10),
        with_dnssec = maps:get(with_dnssec, Args, false),
        dnssec_alg = maps:get(dnssec_alg, Args, 8),
        randomize = Randomize,
        seed = maps:get(seed, Args, undefined),
        count = Count,
        base_name = BaseName,
        output_pattern = maps:get(output_pattern, Args, undefined),
        base_dir = maps:get(base_dir, Args, undefined)
    }.

generate_zones_parallel(Opts) ->
    Count = Opts#opts.count,
    BaseName = Opts#opts.base_name,
    OutputPattern = Opts#opts.output_pattern,
    BaseDir = Opts#opts.base_dir,
    % Ensure base directory exists
    ensure_base_dir(BaseDir),
    % Generate zone configurations
    ZoneConfigs = lists:map(
        fun(Index) ->
            ZoneName = <<BaseName/binary, (integer_to_binary(Index))/binary>>,
            OutputFile =
                case OutputPattern of
                    undefined -> io_lib:format("output-~p.json", [Index]);
                    Pattern -> format_output_pattern(Pattern, Index, ZoneName)
                end,
            {Index, ZoneName, OutputFile}
        end,
        lists:seq(1, Count)
    ),
    io:format("Generating ~p zones in parallel...~n", [Count]),
    StartTime = erlang:monotonic_time(),
    Results = generate_zones_parallel_workers(ZoneConfigs, Opts),
    EndTime = erlang:monotonic_time(),
    DurationNative = EndTime - StartTime,
    DurationFactor = erlang:convert_time_unit(1, millisecond, native),
    DurationMs = erlang:convert_time_unit(DurationNative, native, millisecond),
    % Report results
    Successful = [R || R = {ok, _} <- Results],
    Failed = [R || R = {error, _} <- Results],
    io:format("~nCompleted: ~p successful, ~p failed in ~p ms (~.2f zones/sec)~n", [
        length(Successful),
        length(Failed),
        DurationMs,
        (Count * DurationFactor / DurationNative)
    ]),
    case Failed of
        [] ->
            ok;
        _ ->
            io:format(standard_error, "Failed zones:~n", []),
            [
                io:format(standard_error, "  Zone ~p: ~p~n", [Index, Error])
             || {error, {Index, Error}} <- Failed
            ],
            halt(1)
    end.

generate_zones_parallel_workers(ZoneConfigs, Opts) ->
    Workers = lists:map(
        fun({Index, ZoneName, OutputFile}) ->
            {Pid, Ref} = spawn_monitor(fun() ->
                generate_zone_child(Index, ZoneName, OutputFile, Opts)
            end),
            {Pid, Index, Ref}
        end,
        ZoneConfigs
    ),
    collect_results(Workers, []).

generate_zone_child(Index, ZoneName, OutputFile, Opts) ->
    WorkerOpts = Opts#opts{
        zone_name = ZoneName,
        output_file = OutputFile,
        seed =
            case Opts#opts.seed of
                undefined -> undefined;
                % Different seed per zone for reproducibility
                Seed -> Seed + Index
            end
    },
    generate_zone_internal(WorkerOpts).

% Collect results from all workers
collect_results([], Acc) ->
    lists:reverse(Acc);
collect_results([{Pid, Index, Ref} | Workers], Acc) ->
    receive
        {'DOWN', Ref, process, Pid, normal} ->
            collect_results(Workers, [{ok, Index} | Acc]);
        {'DOWN', Ref, process, Pid, Reason} ->
            % Worker crashed before sending result
            collect_results(Workers, [{error, {Index, Reason}} | Acc])
    end.

format_output_pattern(Pattern, Index, ZoneName) ->
    % Replace %d with index, %s with zone name
    Replaced = re:replace(Pattern, "%d", integer_to_list(Index), [global, {return, list}]),
    re:replace(Replaced, "%s", binary_to_list(ZoneName), [global, {return, list}]).

% Apply base directory to output file path
apply_base_dir(OutputFile, undefined) when is_binary(OutputFile) ->
    binary_to_list(OutputFile);
apply_base_dir(OutputFile, undefined) when is_list(OutputFile) ->
    OutputFile;
apply_base_dir(OutputFile, BaseDir) when is_binary(OutputFile) ->
    apply_base_dir(binary_to_list(OutputFile), BaseDir);
apply_base_dir(OutputFile, BaseDir) when is_list(OutputFile), is_list(BaseDir) ->
    % If output file is already absolute, use it as-is
    case filename:absname(OutputFile) of
        AbsPath when is_list(AbsPath) ->
            % Check if it's an absolute path (Unix: starts with /, Windows: starts with C:\, etc.)
            case filename:pathtype(OutputFile) of
                absolute -> AbsPath;
                _ -> filename:join(BaseDir, OutputFile)
            end
    end.

% Ensure base directory exists, create it if it doesn't
ensure_base_dir(undefined) ->
    ok;
ensure_base_dir(BaseDir) when is_list(BaseDir) ->
    case filelib:is_dir(BaseDir) of
        true ->
            ok;
        false ->
            case file:make_dir(BaseDir) of
                ok ->
                    io:format("Created base directory: ~s~n", [BaseDir]);
                {error, eexist} ->
                    % Directory was created by another process, that's fine
                    ok;
                {error, Reason} ->
                    io:format(standard_error, "Warning: Could not create base directory ~s: ~p~n", [
                        BaseDir, Reason
                    ])
            end
    end.

generate_zone(Opts) ->
    generate_zone_internal(Opts).

generate_zone_internal(Opts) ->
    % Initialize random seed if provided
    case Opts#opts.seed of
        undefined -> ok;
        Seed -> rand:seed(exsplus, {Seed, Seed, Seed})
    end,
    ZoneName = Opts#opts.zone_name,
    Records = generate_records(ZoneName, Opts),
    {RecordsWithDNSSEC, Keys} =
        case Opts#opts.with_dnssec of
            true ->
                {DNSSECRecords, DNSSECKeys} = generate_dnssec_records_and_keys(ZoneName, Opts),
                {Records ++ DNSSECRecords, DNSSECKeys};
            false ->
                {Records, []}
        end,
    Zone = #{
        ~"name" => ZoneName,
        ~"records" => RecordsWithDNSSEC
    },
    ZoneWithKeys =
        case Keys of
            [] -> Zone;
            _ -> Zone#{~"keys" => Keys}
        end,
    % Apply base directory if specified
    OutputFile = apply_base_dir(Opts#opts.output_file, Opts#opts.base_dir),
    % Write single zone to file (not an array)
    JSON = json:encode([ZoneWithKeys]),
    ok = file:write_file(OutputFile, JSON, [raw]).

generate_records(ZoneName, Opts) ->
    SoaRecord = generate_soa(ZoneName, Opts),
    NumRecords = Opts#opts.num_records - 1,
    AdditionalRecords = generate_additional_records(ZoneName, NumRecords, Opts),
    [SoaRecord | AdditionalRecords].

generate_soa(ZoneName, Opts) ->
    MName = <<"ns1.", ZoneName/binary>>,
    RName = <<"admin.", ZoneName/binary>>,
    Serial =
        case Opts#opts.randomize of
            true -> rand:uniform(2147483647);
            false -> 2024010101
        end,
    #{
        ~"name" => ZoneName,
        ~"type" => ~"SOA",
        ~"ttl" => ?DEFAULT_TTL,
        ~"data" => #{
            ~"mname" => MName,
            ~"rname" => RName,
            ~"serial" => Serial,
            ~"refresh" => ?DEFAULT_SOA_REFRESH,
            ~"retry" => ?DEFAULT_SOA_RETRY,
            ~"expire" => ?DEFAULT_SOA_EXPIRE,
            ~"minimum" => ?DEFAULT_SOA_MINIMUM
        }
    }.

generate_additional_records(_ZoneName, 0, _Opts) ->
    [];
generate_additional_records(ZoneName, N, Opts) ->
    RecordTypes = [a, aaaa, ns, mx, cname, txt, srv, caa],
    Type =
        case Opts#opts.randomize of
            true -> lists:nth(rand:uniform(length(RecordTypes)), RecordTypes);
            false -> lists:nth((N rem length(RecordTypes)) + 1, RecordTypes)
        end,
    Record = generate_record_by_type(ZoneName, Type, N, Opts),
    [Record | generate_additional_records(ZoneName, N - 1, Opts)].

generate_record_by_type(ZoneName, a, Index, Opts) ->
    Name =
        case Index rem 3 of
            0 -> ZoneName;
            _ -> <<"host", (integer_to_binary(Index))/binary, ".", ZoneName/binary>>
        end,
    IP =
        case Opts#opts.randomize of
            true -> generate_random_ipv4();
            false -> <<"192.168.1.", (integer_to_binary(Index rem 255))/binary>>
        end,
    #{
        ~"name" => Name,
        ~"type" => ~"A",
        ~"ttl" => ?DEFAULT_TTL,
        ~"data" => #{
            ~"ip" => IP
        }
    };
generate_record_by_type(ZoneName, aaaa, Index, Opts) ->
    Name =
        case Index rem 3 of
            0 -> ZoneName;
            _ -> <<"host", (integer_to_binary(Index))/binary, ".", ZoneName/binary>>
        end,
    IP =
        case Opts#opts.randomize of
            true -> generate_random_ipv6();
            false -> <<"2001:db8::", (integer_to_binary(Index rem 65535))/binary>>
        end,
    #{
        ~"name" => Name,
        ~"type" => ~"AAAA",
        ~"ttl" => ?DEFAULT_TTL,
        ~"data" => #{
            ~"ip" => IP
        }
    };
generate_record_by_type(ZoneName, ns, Index, _Opts) ->
    NSName = <<"ns", (integer_to_binary((Index rem 4) + 1))/binary, ".", ZoneName/binary>>,
    #{
        ~"name" => ZoneName,
        ~"type" => ~"NS",
        ~"ttl" => ?DEFAULT_TTL,
        ~"data" => #{
            ~"dname" => NSName
        }
    };
generate_record_by_type(ZoneName, mx, Index, _Opts) ->
    Preference = (Index rem 10) + 10,
    Exchange = <<"mail", (integer_to_binary(Index rem 3))/binary, ".", ZoneName/binary>>,
    #{
        ~"name" => ZoneName,
        ~"type" => ~"MX",
        ~"ttl" => ?DEFAULT_TTL,
        ~"data" => #{
            ~"preference" => Preference,
            ~"exchange" => Exchange
        }
    };
generate_record_by_type(ZoneName, cname, Index, _Opts) ->
    Name = <<"www.", ZoneName/binary>>,
    Target =
        case Index rem 2 of
            0 -> ZoneName;
            1 -> <<"host", (integer_to_binary(Index))/binary, ".", ZoneName/binary>>
        end,
    #{
        ~"name" => Name,
        ~"type" => ~"CNAME",
        ~"ttl" => 120,
        ~"data" => #{
            ~"dname" => Target
        }
    };
generate_record_by_type(ZoneName, txt, Index, Opts) ->
    Name =
        case Index rem 2 of
            0 -> ZoneName;
            1 -> <<"_service", (integer_to_binary(Index))/binary, ".", ZoneName/binary>>
        end,
    Text =
        case Opts#opts.randomize of
            true -> <<"\"Random text ", (integer_to_binary(rand:uniform(10000)))/binary, "\"">>;
            false -> <<"\"Sample text ", (integer_to_binary(Index))/binary, "\"">>
        end,
    #{
        ~"name" => Name,
        ~"type" => ~"TXT",
        ~"ttl" => ?DEFAULT_TTL,
        ~"data" => #{
            ~"txts" => [Text]
        }
    };
generate_record_by_type(ZoneName, srv, Index, _Opts) ->
    Service = <<"_service", (integer_to_binary(Index rem 5))/binary, "._tcp.", ZoneName/binary>>,
    Priority = Index rem 10,
    Weight = (Index rem 100) + 1,
    Port = 80 + (Index rem 1000),
    Target = <<"server", (integer_to_binary(Index))/binary, ".", ZoneName/binary>>,
    #{
        ~"name" => Service,
        ~"type" => ~"SRV",
        ~"ttl" => ?DEFAULT_TTL,
        ~"data" => #{
            ~"priority" => Priority,
            ~"weight" => Weight,
            ~"port" => Port,
            ~"target" => Target
        }
    };
generate_record_by_type(ZoneName, caa, Index, _Opts) ->
    Flags = 0,
    Tag =
        case Index rem 3 of
            0 -> ~"issue";
            1 -> ~"issuewild";
            2 -> ~"iodef"
        end,
    Value =
        case Tag of
            ~"iodef" -> <<"mailto:admin@", ZoneName/binary>>;
            _ -> ~"letsencrypt.org"
        end,
    #{
        ~"name" => ZoneName,
        ~"type" => ~"CAA",
        ~"ttl" => ?DEFAULT_TTL,
        ~"data" => #{
            ~"flags" => Flags,
            ~"tag" => Tag,
            ~"value" => Value
        }
    }.

generate_random_ipv4() ->
    A = rand:uniform(255),
    B = rand:uniform(255),
    C = rand:uniform(255),
    D = rand:uniform(255),
    list_to_binary(io_lib:format("~p.~p.~p.~p", [A, B, C, D])).

generate_random_ipv6() ->
    Segments = [rand:uniform(65535) || _ <- lists:seq(1, 8)],
    list_to_binary(string:join([integer_to_list(S, 16) || S <- Segments], ":")).

generate_dnssec_records_and_keys(ZoneName, Opts) ->
    Alg = Opts#opts.dnssec_alg,
    {KSKPrivateKey, KSKPublicKeyBin, KSKKeyTag} = generate_key(Alg, ?DNSKEY_KSK_TYPE),
    {ZSKPrivateKey, ZSKPublicKeyBin, ZSKKeyTag} = generate_key(Alg, ?DNSKEY_ZSK_TYPE),
    % Generate DNSKEY record for KSK
    KSKDNSKEYRecord = #{
        ~"name" => ZoneName,
        ~"type" => ~"DNSKEY",
        ~"ttl" => 120,
        ~"data" => #{
            ~"flags" => ?DNSKEY_KSK_TYPE,
            ~"protocol" => ?DNSKEY_PROTOCOL,
            ~"alg" => Alg,
            ~"public_key" => base64:encode(KSKPublicKeyBin),
            ~"key_tag" => KSKKeyTag
        }
    },
    % Generate DNSKEY record for ZSK
    ZSKDNSKEYRecord = #{
        ~"name" => ZoneName,
        ~"type" => ~"DNSKEY",
        ~"ttl" => 120,
        ~"data" => #{
            ~"flags" => ?DNSKEY_ZSK_TYPE,
            ~"protocol" => ?DNSKEY_PROTOCOL,
            ~"alg" => Alg,
            ~"public_key" => base64:encode(ZSKPublicKeyBin),
            ~"key_tag" => ZSKKeyTag
        }
    },
    % Generate CDS record
    CDSRecord = #{
        ~"name" => ZoneName,
        ~"type" => ~"CDS",
        ~"ttl" => 120,
        ~"data" => #{
            ~"keytag" => KSKKeyTag,
            ~"alg" => Alg,
            ~"digest_type" => ?DS_DIGEST_TYPE_SHA256,
            ~"digest" => generate_digest(KSKPublicKeyBin, Alg)
        }
    },
    % Generate CDNSKEY record
    CDNSKEYRecord = #{
        ~"name" => ZoneName,
        ~"type" => ~"CDNSKEY",
        ~"ttl" => 120,
        ~"data" => #{
            ~"flags" => ?DNSKEY_KSK_TYPE,
            ~"protocol" => ?DNSKEY_PROTOCOL,
            ~"alg" => Alg,
            ~"public_key" => base64:encode(KSKPublicKeyBin),
            ~"key_tag" => KSKKeyTag
        }
    },
    Records = [KSKDNSKEYRecord, ZSKDNSKEYRecord, CDSRecord, CDNSKEYRecord],
    Now = erlang:system_time(second),
    % Generate keyset
    Inception = calendar:system_time_to_rfc3339(Now, [{offset, "Z"}]),
    Until = calendar:system_time_to_rfc3339(Now + (365 * 24 * 3600), [{offset, "Z"}]),
    Keys = [
        #{
            ~"ksk" => pem_encode_private_key(KSKPrivateKey, Alg),
            ~"ksk_keytag" => KSKKeyTag,
            ~"ksk_alg" => Alg,
            ~"zsk" => pem_encode_private_key(ZSKPrivateKey, Alg),
            ~"zsk_keytag" => ZSKKeyTag,
            ~"zsk_alg" => Alg,
            ~"inception" => list_to_binary(Inception),
            ~"until" => list_to_binary(Until)
        }
    ],
    {Records, Keys}.

% RSA
generate_key(?DNS_ALG_RSASHA256, Flags) ->
    {_, [E, N, D, P1, P2, E1, E2, C]} = crypto:generate_key(rsa, {2048, 65537}),
    PublicKeyBin = <<(byte_size(E)):8, E/binary, N/binary>>,
    KeyTag = calculate_keytag(Flags, ?DNS_ALG_RSASHA256, PublicKeyBin),
    RsaRec = #'RSAPrivateKey'{
        version = 'two-prime',
        modulus = crypto:bytes_to_integer(N),
        publicExponent = crypto:bytes_to_integer(E),
        privateExponent = crypto:bytes_to_integer(D),
        prime1 = crypto:bytes_to_integer(P1),
        prime2 = crypto:bytes_to_integer(P2),
        exponent1 = crypto:bytes_to_integer(E1),
        exponent2 = crypto:bytes_to_integer(E2),
        coefficient = crypto:bytes_to_integer(C)
    },
    {RsaRec, PublicKeyBin, KeyTag};
% ECDSA P-256
generate_key(?DNS_ALG_ECDSAP256SHA256, Flags) ->
    {PublicKey, PrivateKey} = crypto:generate_key(ecdh, secp256r1),
    KeyTag = calculate_keytag(Flags, ?DNS_ALG_ECDSAP256SHA256, PublicKey),
    EcRec = #'ECPrivateKey'{
        version = 1,
        privateKey = PrivateKey,
        parameters = {namedCurve, ?'secp256r1'},
        publicKey = PublicKey
    },
    {EcRec, PublicKey, KeyTag};
% ECDSA P-384
generate_key(?DNS_ALG_ECDSAP384SHA384, Flags) ->
    {PublicKey, PrivateKey} = crypto:generate_key(ecdh, secp384r1),
    KeyTag = calculate_keytag(Flags, ?DNS_ALG_ECDSAP384SHA384, PublicKey),
    EcRec = #'ECPrivateKey'{
        version = 1,
        privateKey = PrivateKey,
        parameters = {namedCurve, ?'secp384r1'},
        publicKey = PublicKey
    },
    {EcRec, PublicKey, KeyTag};
% Ed25519
generate_key(?DNS_ALG_ED25519, Flags) ->
    {PublicKey, PrivateKey} = crypto:generate_key(eddsa, ed25519),
    KeyTag = calculate_keytag(Flags, ?DNS_ALG_ED25519, PublicKey),
    EdRec = #'OneAsymmetricKey'{
        version = v1,
        privateKeyAlgorithm = #'PrivateKeyInfo_privateKeyAlgorithm'{
            algorithm = ?'id-Ed25519',
            parameters = asn1_NOVALUE
        },
        privateKey = public_key:der_encode('CurvePrivateKey', PrivateKey)
    },
    {EdRec, PublicKey, KeyTag};
% Ed448
generate_key(?DNS_ALG_ED448, Flags) ->
    {PublicKey, PrivateKey} = crypto:generate_key(eddsa, ed448),
    KeyTag = calculate_keytag(Flags, ?DNS_ALG_ED448, PublicKey),
    EdRec = #'OneAsymmetricKey'{
        version = v1,
        privateKeyAlgorithm = #'PrivateKeyInfo_privateKeyAlgorithm'{
            algorithm = ?'id-Ed448',
            parameters = asn1_NOVALUE
        },
        privateKey = public_key:der_encode('CurvePrivateKey', PrivateKey)
    },
    {EdRec, PublicKey, KeyTag}.

% Keytag calculation (RFC 4034 Appendix B)
calculate_keytag(Flags, Alg, PublicKey) ->
    WireFormat = <<Flags:16, ?DNSKEY_PROTOCOL:8, Alg:8, PublicKey/binary>>,
    % Calculate sum of all 16-bit words
    Size = byte_size(WireFormat),
    Words = [X || <<X:16>> <= WireFormat],
    Sum = lists:sum(Words),
    % Handle odd byte at the end if present
    FinalSum =
        case Size rem 2 of
            0 ->
                Sum;
            1 ->
                <<LastByte:8>> = binary:part(WireFormat, Size - 1, 1),
                Sum + (LastByte bsl 8)
        end,
    % Add carry and mask to 16 bits
    (FinalSum + (FinalSum bsr 16)) band 16#FFFF.

generate_digest(PublicKey, _Alg) ->
    % Simplified digest generation - in production this should follow RFC 4034
    Digest = crypto:hash(sha256, PublicKey),
    string:uppercase(binary_to_list(binary:encode_hex(Digest))).

pem_encode_private_key(Record, ?DNS_ALG_RSASHA256) ->
    to_pem('RSAPrivateKey', Record);
pem_encode_private_key(Record, ?DNS_ALG_ECDSAP256SHA256) ->
    to_pem('ECPrivateKey', Record);
pem_encode_private_key(Record, ?DNS_ALG_ECDSAP384SHA384) ->
    to_pem('ECPrivateKey', Record);
pem_encode_private_key(Record, ?DNS_ALG_ED25519) ->
    to_pem('PrivateKeyInfo', Record);
pem_encode_private_key(Record, ?DNS_ALG_ED448) ->
    to_pem('PrivateKeyInfo', Record).

to_pem(Type, KeyRecord) ->
    PemEntry = public_key:pem_entry_encode(Type, KeyRecord),
    public_key:pem_encode([PemEntry]).
