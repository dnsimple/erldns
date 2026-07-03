-module(dnssec_SUITE).
-compile([export_all, nowarn_export_all]).

-behaviour(ct_suite).

-include_lib("stdlib/include/assert.hrl").
-include_lib("dns_erlang/include/dns.hrl").

-spec all() -> [ct_suite:ct_test_def()].
all() ->
    [
        verify_ksk_signed,
        verify_ksk_signed_alg13,
        verify_ksk_signed_alg14,
        verify_ksk_signed_alg15,
        verify_ksk_signed_alg16,
        verify_zsk_signed,
        verify_zsk_signed_alg13,
        verify_zsk_signed_alg14,
        verify_zsk_signed_alg15,
        verify_zsk_signed_alg16,
        test_signer_selection_logic,
        test_requires_key_signing_key_function,
        find_rrsigs_deduplicates_by_name_and_type,
        add_nsec_type_mapper_accumulates,
        map_nsec_rr_types_widens_custom_types
    ].

-spec init_per_suite(ct_suite:ct_config()) -> ct_suite:ct_config().
init_per_suite(Config) ->
    application:unset_env(erldns, zones),
    Config.

-spec end_per_suite(ct_suite:ct_config()) -> term().
end_per_suite(_Config) ->
    application:unset_env(erldns, zones),
    ok.

-spec init_per_testcase(ct_suite:ct_testcase(), ct_suite:ct_config()) -> ct_suite:ct_config().
init_per_testcase(_, Config) ->
    FileName = filename:join([code:priv_dir(erldns), "zones/example.com.json"]),
    application:set_env(erldns, zones, #{path => FileName, strict => true}),
    erldns_zones:start_link(),
    Config.

-spec end_per_testcase(ct_suite:ct_testcase(), ct_suite:ct_config()) -> term().
end_per_testcase(_, _Config) ->
    application:unset_env(erldns, zones),
    ok.

verify_ksk_signed(_) ->
    Name = dns_domain:to_lower(~"example-dnssec0.com"),
    Labels = dns_domain:split(Name),
    QType = ?DNS_TYPE_A,
    Q = #dns_query{name = Name, type = QType},
    A = #dns_rr{name = Name, type = QType, data = #dns_rrdata_a{ip = {1, 2, 3, 4}}},
    Ad = #dns_optrr{dnssec = true},
    Msg0 = #dns_message{
        qc = 1, anc = 1, auc = 1, questions = [Q], answers = [A], additional = [Ad]
    },
    Zone = erldns_zone_cache:get_authoritative_zone(Labels),
    Msg1 = erldns_dnssec:handle(Msg0, Zone, Labels, Name, QType, #{}, true),
    ?assertMatch(
        #dns_message{
            answers =
                [
                    A,
                    #dns_rr{
                        name = Name,
                        type = ?DNS_TYPE_RRSIG,
                        data = #dns_rrdata_rrsig{
                            keytag = 49016,
                            signers_name = Name
                        }
                    }
                ]
        },
        Msg1
    ).

verify_ksk_signed_alg13(_) ->
    Name = dns_domain:to_lower(~"example-dnssec-13.com"),
    Labels = dns_domain:split(Name),
    QType = ?DNS_TYPE_A,
    Q = #dns_query{name = Name, type = QType},
    A = #dns_rr{name = Name, type = QType, data = #dns_rrdata_a{ip = {1, 2, 3, 4}}},
    Ad = #dns_optrr{dnssec = true},
    Msg0 = #dns_message{
        qc = 1, anc = 1, auc = 1, questions = [Q], answers = [A], additional = [Ad]
    },
    Zone = erldns_zone_cache:get_authoritative_zone(Labels),
    Msg1 = erldns_dnssec:handle(Msg0, Zone, Labels, Name, QType, #{}, true),
    ?assertMatch(
        #dns_message{
            answers =
                [
                    A,
                    #dns_rr{
                        name = Name,
                        type = ?DNS_TYPE_RRSIG,
                        data = #dns_rrdata_rrsig{
                            keytag = 25428,
                            signers_name = Name
                        }
                    }
                ]
        },
        Msg1
    ).

verify_ksk_signed_alg14(_) ->
    Name = dns_domain:to_lower(~"example-dnssec-14.com"),
    Labels = dns_domain:split(Name),
    QType = ?DNS_TYPE_A,
    Q = #dns_query{name = Name, type = QType},
    A = #dns_rr{name = Name, type = QType, data = #dns_rrdata_a{ip = {1, 2, 3, 4}}},
    Ad = #dns_optrr{dnssec = true},
    Msg0 = #dns_message{
        qc = 1, anc = 1, auc = 1, questions = [Q], answers = [A], additional = [Ad]
    },
    Zone = erldns_zone_cache:get_authoritative_zone(Labels),
    Msg1 = erldns_dnssec:handle(Msg0, Zone, Labels, Name, QType, #{}, true),
    ?assertMatch(
        #dns_message{
            answers =
                [
                    A,
                    #dns_rr{
                        name = Name,
                        type = ?DNS_TYPE_RRSIG,
                        data = #dns_rrdata_rrsig{
                            keytag = 25428,
                            signers_name = Name
                        }
                    }
                ]
        },
        Msg1
    ).

verify_zsk_signed(_) ->
    Name = dns_domain:to_lower(~"example-dnssec0.com"),
    Labels = dns_domain:split(Name),
    QType = ?DNS_TYPE_CDNSKEY,
    CDSRecord = #dns_rr{
        name = ~"example.com",
        type = ?DNS_TYPE_CDNSKEY,
        ttl = 120,
        data = #dns_rrdata_cds{
            keytag = 0,
            alg = 0,
            digest_type = 0,
            digest = ~"00"
        }
    },

    Q = #dns_query{name = Name, type = QType},
    A = #dns_rr{name = Name, type = QType, data = CDSRecord},
    Ad = #dns_optrr{dnssec = true},
    Msg0 = #dns_message{
        qc = 1, anc = 1, auc = 1, questions = [Q], answers = [A], additional = [Ad]
    },
    Zone = erldns_zone_cache:get_authoritative_zone(Labels),
    Msg1 = erldns_dnssec:handle(Msg0, Zone, Labels, Name, QType, #{}, true),
    ?assertMatch(
        #dns_message{
            answers =
                [
                    A,
                    #dns_rr{
                        name = Name,
                        type = ?DNS_TYPE_RRSIG,
                        data = #dns_rrdata_rrsig{
                            keytag = 37440,
                            signers_name = Name
                        }
                    }
                ]
        },
        Msg1
    ).

verify_zsk_signed_alg13(_) ->
    Name = dns_domain:to_lower(~"example-dnssec-13.com"),
    Labels = dns_domain:split(Name),
    QType = ?DNS_TYPE_CDNSKEY,
    CDSRecord = #dns_rr{
        name = ~"example.com",
        type = ?DNS_TYPE_CDNSKEY,
        ttl = 120,
        data = #dns_rrdata_cds{
            keytag = 57270,
            alg = 13,
            digest_type = 2,
            digest = ~"240D52C69E20328DF0FB99FB4FB2DB80796F43F2D9B84DDA3BEC5A5D7FAA3A63"
        }
    },
    Q = #dns_query{name = Name, type = QType},
    A = #dns_rr{name = Name, type = QType, data = CDSRecord},
    Ad = #dns_optrr{dnssec = true},
    Msg0 = #dns_message{
        qc = 1, anc = 1, auc = 1, questions = [Q], answers = [A], additional = [Ad]
    },
    Zone = erldns_zone_cache:get_authoritative_zone(Labels),
    Msg1 = erldns_dnssec:handle(Msg0, Zone, Labels, Name, QType, #{}, true),
    ?assertMatch(
        #dns_message{
            answers =
                [
                    A,
                    #dns_rr{
                        name = Name,
                        type = ?DNS_TYPE_RRSIG,
                        data = #dns_rrdata_rrsig{
                            keytag = 57270,
                            signers_name = Name
                        }
                    }
                ]
        },
        Msg1
    ).

verify_zsk_signed_alg14(_) ->
    Name = dns_domain:to_lower(~"example-dnssec-14.com"),
    Labels = dns_domain:split(Name),
    QType = ?DNS_TYPE_CDNSKEY,
    CDSRecord = #dns_rr{
        name = ~"example.com",
        type = ?DNS_TYPE_CDNSKEY,
        ttl = 120,
        data = #dns_rrdata_cds{
            keytag = 57270,
            alg = 14,
            digest_type = 2,
            digest = ~"240D52C69E20328DF0FB99FB4FB2DB80796F43F2D9B84DDA3BEC5A5D7FAA3A63"
        }
    },
    Q = #dns_query{name = Name, type = QType},
    A = #dns_rr{name = Name, type = QType, data = CDSRecord},
    Ad = #dns_optrr{dnssec = true},
    Msg0 = #dns_message{
        qc = 1, anc = 1, auc = 1, questions = [Q], answers = [A], additional = [Ad]
    },
    Zone = erldns_zone_cache:get_authoritative_zone(Labels),
    Msg1 = erldns_dnssec:handle(Msg0, Zone, Labels, Name, QType, #{}, true),
    ?assertMatch(
        #dns_message{
            answers =
                [
                    A,
                    #dns_rr{
                        name = Name,
                        type = ?DNS_TYPE_RRSIG,
                        data = #dns_rrdata_rrsig{
                            keytag = 57270,
                            signers_name = Name
                        }
                    }
                ]
        },
        Msg1
    ).

verify_ksk_signed_alg15(_) ->
    Name = dns_domain:to_lower(~"example-dnssec-15.com"),
    Labels = dns_domain:split(Name),
    QType = ?DNS_TYPE_A,
    Q = #dns_query{name = Name, type = QType},
    A = #dns_rr{name = Name, type = QType, data = #dns_rrdata_a{ip = {1, 2, 3, 4}}},
    Ad = #dns_optrr{dnssec = true},
    Msg0 = #dns_message{
        qc = 1, anc = 1, auc = 1, questions = [Q], answers = [A], additional = [Ad]
    },
    Zone = erldns_zone_cache:get_authoritative_zone(Labels),
    Msg1 = erldns_dnssec:handle(Msg0, Zone, Labels, Name, QType, #{}, true),
    ?assertMatch(
        #dns_message{
            answers =
                [
                    A,
                    #dns_rr{
                        name = Name,
                        type = ?DNS_TYPE_RRSIG,
                        data = #dns_rrdata_rrsig{
                            keytag = 25428,
                            signers_name = Name
                        }
                    }
                ]
        },
        Msg1
    ).

verify_ksk_signed_alg16(_) ->
    Name = dns_domain:to_lower(~"example-dnssec-16.com"),
    Labels = dns_domain:split(Name),
    QType = ?DNS_TYPE_A,
    Q = #dns_query{name = Name, type = QType},
    A = #dns_rr{name = Name, type = QType, data = #dns_rrdata_a{ip = {1, 2, 3, 4}}},
    Ad = #dns_optrr{dnssec = true},
    Msg0 = #dns_message{
        qc = 1, anc = 1, auc = 1, questions = [Q], answers = [A], additional = [Ad]
    },
    Zone = erldns_zone_cache:get_authoritative_zone(Labels),
    Msg1 = erldns_dnssec:handle(Msg0, Zone, Labels, Name, QType, #{}, true),
    ?assertMatch(
        #dns_message{
            answers =
                [
                    A,
                    #dns_rr{
                        name = Name,
                        type = ?DNS_TYPE_RRSIG,
                        data = #dns_rrdata_rrsig{
                            keytag = 25428,
                            signers_name = Name
                        }
                    }
                ]
        },
        Msg1
    ).

verify_zsk_signed_alg15(_) ->
    Name = dns_domain:to_lower(~"example-dnssec-15.com"),
    Labels = dns_domain:split(Name),
    QType = ?DNS_TYPE_CDNSKEY,
    CDSRecord = #dns_rr{
        name = ~"example.com",
        type = ?DNS_TYPE_CDNSKEY,
        ttl = 120,
        data = #dns_rrdata_cds{
            keytag = 57270,
            alg = 15,
            digest_type = 2,
            digest = ~"240D52C69E20328DF0FB99FB4FB2DB80796F43F2D9B84DDA3BEC5A5D7FAA3A63"
        }
    },
    Q = #dns_query{name = Name, type = QType},
    A = #dns_rr{name = Name, type = QType, data = CDSRecord},
    Ad = #dns_optrr{dnssec = true},
    Msg0 = #dns_message{
        qc = 1, anc = 1, auc = 1, questions = [Q], answers = [A], additional = [Ad]
    },
    Zone = erldns_zone_cache:get_authoritative_zone(Labels),
    Msg1 = erldns_dnssec:handle(Msg0, Zone, Labels, Name, QType, #{}, true),
    ?assertMatch(
        #dns_message{
            answers =
                [
                    A,
                    #dns_rr{
                        name = Name,
                        type = ?DNS_TYPE_RRSIG,
                        data = #dns_rrdata_rrsig{
                            keytag = 57270,
                            signers_name = Name
                        }
                    }
                ]
        },
        Msg1
    ).

verify_zsk_signed_alg16(_) ->
    Name = dns_domain:to_lower(~"example-dnssec-16.com"),
    Labels = dns_domain:split(Name),
    QType = ?DNS_TYPE_CDNSKEY,
    CDSRecord = #dns_rr{
        name = ~"example.com",
        type = ?DNS_TYPE_CDNSKEY,
        ttl = 120,
        data = #dns_rrdata_cds{
            keytag = 57270,
            alg = 16,
            digest_type = 2,
            digest = ~"240D52C69E20328DF0FB99FB4FB2DB80796F43F2D9B84DDA3BEC5A5D7FAA3A63"
        }
    },
    Q = #dns_query{name = Name, type = QType},
    A = #dns_rr{name = Name, type = QType, data = CDSRecord},
    Ad = #dns_optrr{dnssec = true},
    Msg0 = #dns_message{
        qc = 1, anc = 1, auc = 1, questions = [Q], answers = [A], additional = [Ad]
    },
    Zone = erldns_zone_cache:get_authoritative_zone(Labels),
    Msg1 = erldns_dnssec:handle(Msg0, Zone, Labels, Name, QType, #{}, true),
    ?assertMatch(
        #dns_message{
            answers =
                [
                    A,
                    #dns_rr{
                        name = Name,
                        type = ?DNS_TYPE_RRSIG,
                        data = #dns_rrdata_rrsig{
                            keytag = 57270,
                            signers_name = Name
                        }
                    }
                ]
        },
        Msg1
    ).

%% Test the requires_key_signing_key helper function
test_requires_key_signing_key_function(_Config) ->
    % Test CDS record
    CDSRecord = #dns_rr{
        name = ~"example.com",
        type = ?DNS_TYPE_CDS,
        ttl = 120,
        data = #dns_rrdata_cds{
            keytag = 12345,
            alg = 8,
            digest_type = 2,
            digest = ~"abcdef1234567890"
        }
    },

    % Test CDNSKEY record
    CDNSKEYRecord = #dns_rr{
        name = ~"example.com",
        type = ?DNS_TYPE_CDNSKEY,
        ttl = 120,
        data = #dns_rrdata_dnskey{
            flags = 257,
            protocol = 3,
            alg = 8,
            public_key = ~"test_public_key"
        }
    },

    % Test A record
    ARecord = #dns_rr{
        name = ~"example.com",
        type = ?DNS_TYPE_A,
        ttl = 300,
        data = #dns_rrdata_a{ip = {192, 168, 1, 1}}
    },

    % Test that CDS requires key-signing-key
    ?assert(erldns_dnssec:requires_key_signing_key([CDSRecord])),

    % Test that CDNSKEY requires key-signing-key
    ?assert(erldns_dnssec:requires_key_signing_key([CDNSKEYRecord])),

    % Test that mixed records with CDS/CDNSKEY require key-signing-key
    ?assert(erldns_dnssec:requires_key_signing_key([ARecord, CDSRecord])),
    ?assert(erldns_dnssec:requires_key_signing_key([CDNSKEYRecord, ARecord])),

    % Test that other records don't require key-signing-key
    ?assertNot(erldns_dnssec:requires_key_signing_key([ARecord])),

    % Test empty list
    ?assertNot(erldns_dnssec:requires_key_signing_key([])).

%% Test the signer selection logic in choose_signer_for_rrset
test_signer_selection_logic(_Config) ->
    ZoneName = ~"example.com",

    % Test CDS record should use key signer
    CDSRecord = #dns_rr{
        name = ZoneName,
        type = ?DNS_TYPE_CDS,
        ttl = 120,
        data = #dns_rrdata_cds{
            keytag = 12345,
            alg = 8,
            digest_type = 2,
            digest = ~"abcdef1234567890"
        }
    },

    % Test CDNSKEY record should use key signer
    CDNSKEYRecord = #dns_rr{
        name = ZoneName,
        type = ?DNS_TYPE_CDNSKEY,
        ttl = 120,
        data = #dns_rrdata_dnskey{
            flags = 257,
            protocol = 3,
            alg = 8,
            public_key = ~"test_public_key"
        }
    },

    % Test A record should use zone signer
    ARecord = #dns_rr{
        name = ZoneName,
        type = ?DNS_TYPE_A,
        ttl = 300,
        data = #dns_rrdata_a{ip = {192, 168, 1, 1}}
    },

    % Get signers for different record types
    CDSSigner = erldns_dnssec:choose_signer_for_rrset(ZoneName, [CDSRecord]),
    CDNSKEYSigner = erldns_dnssec:choose_signer_for_rrset(ZoneName, [CDNSKEYRecord]),
    ASigner = erldns_dnssec:choose_signer_for_rrset(ZoneName, [ARecord]),

    % Verify they are functions
    ?assert(is_function(CDSSigner)),
    ?assert(is_function(CDNSKEYSigner)),
    ?assert(is_function(ASigner)),

    % These are internal tests - we can't easily verify which signer is returned
    % without exposing more internals, but the function should work without error
    ok.

%% Regression: find_rrsigs must deduplicate by (name, type) so that duplicate
%% records in the message do not produce duplicate RRSIGs. The implementation
%% uses lists:usort/2 with a comparison that must be a total order (e.g.
%% (N1 < N2) orelse (N1 =:= N2 andalso T1 =< T2)); using N1 =< N2 andalso T1 =< T2
%% is not a total order and fails to deduplicate when (A,B) and (B,A) are both false
%% (e.g. name A < name B but type A > type B).
find_rrsigs_deduplicates_by_name_and_type(_Config) ->
    Name = dns_domain:to_lower(~"example.com"),
    A = #dns_rr{name = Name, type = ?DNS_TYPE_AAAA, data = <<>>},
    B = #dns_rr{name = <<"www.", Name/binary>>, type = ?DNS_TYPE_A, data = <<>>},
    R1 = erldns_dnssec:find_unique_lookups([A, B]),
    R2 = erldns_dnssec:find_unique_lookups([A, B, A]),
    ?assertEqual(
        length(R1),
        length(R2),
        "find_unique_lookups must deduplicate by (name, type); [A,B,A] must yield same RRSIG count as [A,B]"
    ),
    ?assertEqual(
        lists:sort(R1),
        lists:sort(R2),
        "find_unique_lookups must deduplicate by (name, type); duplicate records must not duplicate RRSIGs"
    ).

%% add_nsec_type_mapper/3 creates the map on first use and folds each record type to the mapper fun.
add_nsec_type_mapper_accumulates(_Config) ->
    Fun1 = fun(_, _) -> [?DNS_TYPE_A] end,
    Fun2 = fun(_, _) -> [?DNS_TYPE_CNAME] end,
    Opts0 = #{},
    Opts1 = erldns_dnssec:add_nsec_type_mapper(Opts0, [30001], Fun1),
    Opts2 = erldns_dnssec:add_nsec_type_mapper(Opts1, [30002], Fun2),
    ?assertMatch(#{nsec_type_mappers := #{30001 := Fun1, 30002 := Fun2}}, Opts2).

%% map_nsec_rr_types/3 widens custom record types using the registered mappers; with no mappers it
%% returns the input unchanged.
map_nsec_rr_types_widens_custom_types(_Config) ->
    Types = [2, 30001, 46],
    ?assertEqual(Types, erldns_dnssec:map_nsec_rr_types(?DNS_TYPE_A, Types, #{})),
    Mappers = #{30001 => fun(_, _) -> [?DNS_TYPE_A] end},
    ?assertEqual(
        [?DNS_TYPE_A, 2, 46],
        erldns_dnssec:map_nsec_rr_types(?DNS_TYPE_A, Types, Mappers)
    ).
