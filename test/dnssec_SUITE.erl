-module(dnssec_SUITE).
-compile([export_all, nowarn_export_all]).

-behaviour(ct_suite).

-include_lib("stdlib/include/assert.hrl").
-include_lib("dns_erlang/include/dns.hrl").
-include_lib("erldns/include/erldns.hrl").

-define(DELEGATION_ZONE, ~"example-delegation.com").

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
        map_nsec_rr_types_widens_custom_types,
        next_dname_prepends_null_label,
        next_dname_appends_null_octet_at_254,
        next_dname_increments_leftmost_label_at_255,
        next_dname_skips_uppercase_ascii,
        next_dname_ascends_past_saturated_label,
        next_dname_stops_at_the_zone_apex,
        nsec_signed_for_max_length_qname,
        negative_answer_trims_the_soa_and_its_rrsig,
        referral_below_secure_delegation_carries_ds,
        referral_below_insecure_delegation_denies_ds_at_the_cut,
        ns_query_at_secure_delegation_is_a_referral_with_ds,
        cname_into_delegation_signs_the_chain_but_not_the_ns,
        nodata_at_insecure_delegation_omits_glue_from_the_nsec,
        ds_query_at_secure_delegation_is_answered,
        ds_query_below_a_cut_is_a_referral,
        nested_cut_refers_to_the_topmost_delegation,
        delegation_proof_is_owned_by_the_lowercased_name,
        sections_of_the_request_are_dropped,
        error_from_the_resolver_is_left_alone,
        delegation_nsec_ttl_follows_the_soa,
        zone_signing_skips_delegation_ns_glue_and_occluded_records,
        rrset_signing_skips_delegation_ns_and_signs_ds
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
    erldns_zone_cache:delete_zone(?DELEGATION_ZONE),
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
    Msg1 = erldns_dnssec:handle(Msg0, Zone, Labels, Name, QType, none, #{}, true),
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
    Msg1 = erldns_dnssec:handle(Msg0, Zone, Labels, Name, QType, none, #{}, true),
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
    Msg1 = erldns_dnssec:handle(Msg0, Zone, Labels, Name, QType, none, #{}, true),
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
    Msg1 = erldns_dnssec:handle(Msg0, Zone, Labels, Name, QType, none, #{}, true),
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
    Msg1 = erldns_dnssec:handle(Msg0, Zone, Labels, Name, QType, none, #{}, true),
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
    Msg1 = erldns_dnssec:handle(Msg0, Zone, Labels, Name, QType, none, #{}, true),
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
    Msg1 = erldns_dnssec:handle(Msg0, Zone, Labels, Name, QType, none, #{}, true),
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
    Msg1 = erldns_dnssec:handle(Msg0, Zone, Labels, Name, QType, none, #{}, true),
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
    Msg1 = erldns_dnssec:handle(Msg0, Zone, Labels, Name, QType, none, #{}, true),
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
    Msg1 = erldns_dnssec:handle(Msg0, Zone, Labels, Name, QType, none, #{}, true),
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

%% RFC 4471 §3.1.2 step 1, the case every real query takes: a name with room to spare gets a
%% leading label of one zero octet.
next_dname_prepends_null_label(_Config) ->
    QName = ~"foo.example.com",
    Next = next_dname(QName),
    ?assertEqual(~"\000.foo.example.com", Next),
    assert_valid_successor(QName, Next).

%% RFC 4471 §3.1.2 step 2: at 254 octets the leading label no longer fits, but a zero octet can
%% still be appended inside the leftmost label for a cost of one.
next_dname_appends_null_octet_at_254(_Config) ->
    QName = name_of_wire_size(254, ~"leftmost", ~"example.com"),
    [Leftmost | Rest] = dns_domain:split(QName),
    Next = next_dname(QName),
    ?assertEqual([<<Leftmost/binary, 0>> | Rest], dns_domain:split(Next)),
    ?assertEqual(255, byte_size(dns_domain:to_wire(Next))),
    assert_valid_successor(QName, Next).

%% RFC 4471 §3.1.2 step 3, and the regression for the production crash: at the 255-octet ceiling
%% nothing can be appended, so the right-most octet below 0xff is incremented in place. The label
%% lengths are the shape that crashed -- nine labels landing exactly on the ceiling -- built from
%% synthetic content.
next_dname_increments_leftmost_label_at_255(_Config) ->
    [Leftmost | Rest] =
        Labels = [binary:copy(~"a", Len) || Len <- [40, 13, 60, 16, 34, 9, 63, 7, 3]],
    QName = dns_domain:join(Labels),
    ?assertEqual(255, byte_size(dns_domain:to_wire(QName))),
    Next = next_dname(QName),
    Incremented = <<(binary:part(Leftmost, 0, 39))/binary, $b>>,
    ?assertEqual([Incremented | Rest], dns_domain:split(Next)),
    assert_valid_successor(QName, Next).

%% RFC 4471 §3.1.2 step 3 skips uppercase US-ASCII: canonical order compares names lowercased
%% (RFC 4034 §6.1), so 0x41-0x5a never occur in a canonical name and $@ is followed by $[.
next_dname_skips_uppercase_ascii(_Config) ->
    QName = name_of_wire_size(255, ~"trailing@", ~"example.com"),
    [_ | Rest] = dns_domain:split(QName),
    Next = next_dname(QName),
    ?assertEqual([~"trailing[" | Rest], dns_domain:split(Next)),
    assert_valid_successor(QName, Next).

%% RFC 4471 §3.1.2 step 4: a leftmost label of nothing but 0xff cannot be incremented, so it is
%% dropped. The successor is then step 2's action on the label beneath it -- `bar\000...', the true
%% immediate successor -- and not step 3's `bas...', which would claim an empty span over names
%% such as `barx...' that exist and are representable.
next_dname_ascends_past_saturated_label(_Config) ->
    Saturated = binary:copy(<<16#ff>>, 63),
    QName = name_of_wire_size(255, <<Saturated/binary, ".bar">>, ~"example.com"),
    [Saturated, ~"bar" | Rest] = dns_domain:split(QName),
    Next = next_dname(QName),
    ?assertEqual([~"bar\000" | Rest], dns_domain:split(Next)),
    assert_valid_successor(QName, Next).

%% The ascent stops at the zone apex. Growing the apex's own left-most label would name a sibling
%% of the zone, and the Next Domain Name is a name in this zone (RFC 4034 §4.1.1); that section's
%% rule for the last NSEC of a zone gives the apex instead. Reachable only for an apex long enough
%% that one saturated label below it reaches the ceiling, so 190 octets or more.
next_dname_stops_at_the_zone_apex(_Config) ->
    Label = fun(Len) -> binary:copy(~"a", Len) end,
    ZoneName =
        <<(Label(48))/binary, ".", (Label(63))/binary, ".", (Label(63))/binary, ".example.com">>,
    ?assertEqual(190, byte_size(dns_domain:to_wire(ZoneName))),
    QName = <<(binary:copy(<<16#ff>>, 63))/binary, ".", ZoneName/binary>>,
    ?assertEqual(254, byte_size(dns_domain:to_wire(QName))),
    ?assertEqual(ZoneName, next_dname(QName, ZoneName)).

%% End to end: the compact denial-of-existence NSEC for a max-length QNAME is built and signed
%% instead of raising `name_too_long' out of the RRSIG canonicalisation.
nsec_signed_for_max_length_qname(_Config) ->
    ZoneName = dns_domain:to_lower(~"example-dnssec0.com"),
    QName = name_of_wire_size(255, ~"nonexistent", ZoneName),
    QLabels = dns_domain:split(QName),
    QType = ?DNS_TYPE_CNAME,
    Msg0 = #dns_message{
        qc = 1,
        questions = [#dns_query{name = QName, type = QType}],
        additional = [#dns_optrr{dnssec = true}]
    },
    Zone = erldns_zone_cache:get_authoritative_zone(QLabels),
    #dns_message{authority = Authority} =
        erldns_dnssec:handle(Msg0, Zone, QLabels, QName, QType, none, #{}, true),
    Nsec = lists:keyfind(?DNS_TYPE_NSEC, #dns_rr.type, Authority),
    ?assertMatch(#dns_rr{name = QName, data = #dns_rrdata_nsec{}}, Nsec),
    ?assertMatch(
        #dns_rr{name = QName, data = #dns_rrdata_rrsig{type_covered = ?DNS_TYPE_NSEC}},
        lists:keyfind(?DNS_TYPE_RRSIG, #dns_rr.type, Authority)
    ),
    #dns_rr{data = #dns_rrdata_nsec{next_dname = Next}} = Nsec,
    assert_valid_successor(QName, Next).

%% Every name the ladder cases build sits two labels below its zone apex, which is all
%% `next_dname/3' needs of the zone besides its name.
next_dname(QName) ->
    Labels = dns_domain:split(QName),
    next_dname(QName, dns_domain:join(lists:nthtail(length(Labels) - 2, Labels))).

next_dname(QName, ZoneName) ->
    Zone = #zone{labels = dns_domain:split(ZoneName), name = ZoneName},
    erldns_dnssec:next_dname(QName, dns_domain:split(QName), Zone).

%% The two invariants every branch of the ladder owes: the successor is encodable at all, which is
%% what the production crash violated, and it sorts after its input, without which the NSEC would
%% not deny anything.
assert_valid_successor(QName, Next) ->
    ?assert(byte_size(dns_domain:to_wire(Next)) =< 255),
    ?assert(sorts_before(QName, Next)).

%% Canonical DNS name order (RFC 4034 §6.1) is Erlang term order over the labels reversed: lists
%% compare element by element, and binaries octet by octet with the shorter of two prefixes first,
%% which is how labels sort and how a parent sorts before its children. Every name here is already
%% lowercase, so no canonicalisation is needed first.
sorts_before(A, B) ->
    lists:reverse(dns_domain:split(A)) < lists:reverse(dns_domain:split(B)).

%% A name ending in Suffix, with Leftmost as its first label and filler labels in between, whose
%% wire encoding is exactly Size octets.
name_of_wire_size(Size, Leftmost, Suffix) ->
    name_of_wire_size(Size, Leftmost, Suffix, <<>>).

name_of_wire_size(Size, Leftmost, Suffix, Filler) ->
    Candidate = <<Leftmost/binary, ".", Filler/binary, Suffix/binary>>,
    case Size - byte_size(dns_domain:to_wire(Candidate)) of
        0 ->
            Candidate;
        Gap when 0 < Gap ->
            %% Never leave a gap of one, which no label can fill: a label costs its own length
            %% plus a length octet.
            Chunk =
                case 63 < Gap - 1 of
                    true -> 62;
                    false -> Gap - 1
                end,
            Label = binary:copy(~"a", Chunk),
            name_of_wire_size(Size, Leftmost, Suffix, <<Filler/binary, Label/binary, ".">>)
    end.

%% RFC 2308 §3 with DNSSEC: in a negative answer the SOA in the authority section and the RRSIG
%% covering it are both served at the SOA MINIMUM, so the RRSet and its signature agree
%% (RFC 4034 §3) and the signed original TTL is untouched. A positive answer for the SOA keeps
%% the zone TTL on both, which is what #264 protected.
negative_answer_trims_the_soa_and_its_rrsig(_) ->
    ZoneName = dns_domain:to_lower(~"example-dnssec0.com"),
    ZoneLabels = dns_domain:split(ZoneName),
    #zone{authority = [Soa]} = Zone = erldns_zone_cache:get_authoritative_zone(ZoneLabels),
    ?assertMatch(#dns_rr{ttl = 100000, data = #dns_rrdata_soa{minimum = 86400}}, Soa),
    Do = #dns_optrr{dnssec = true},
    QName = ~"nx.example-dnssec0.com",
    QLabels = dns_domain:split(QName),
    %% The resolver pipe has already trimmed the SOA by the time this pipe runs; the RRSIG
    %% covering it is only appended here and must be trimmed to match.
    TrimmedSoa = Soa#dns_rr{ttl = 86400},
    Negative0 = #dns_message{
        qc = 1,
        auc = 1,
        questions = [#dns_query{name = QName, type = ?DNS_TYPE_A}],
        authority = [TrimmedSoa],
        additional = [Do]
    },
    Negative = erldns_dnssec:handle(Negative0, Zone, QLabels, QName, ?DNS_TYPE_A, none, #{}, true),
    Authority = Negative#dns_message.authority,
    ?assertMatch([#dns_rr{ttl = 86400}], lists:filter(fun erldns_records:is_soa/1, Authority)),
    ?assertMatch(
        [#dns_rr{ttl = 86400, data = #dns_rrdata_rrsig{original_ttl = 100000}}],
        lists:filter(fun erldns_records:is_soa_rrsig/1, Authority)
    ),
    ?assertMatch(
        [#dns_rr{ttl = 86400}],
        [RR || #dns_rr{type = ?DNS_TYPE_NSEC} = RR <- Authority]
    ),
    Positive0 = #dns_message{
        qc = 1,
        anc = 1,
        questions = [#dns_query{name = ZoneName, type = ?DNS_TYPE_SOA}],
        answers = [Soa],
        additional = [Do]
    },
    Positive = erldns_dnssec:handle(
        Positive0, Zone, ZoneLabels, ZoneName, ?DNS_TYPE_SOA, none, #{}, true
    ),
    Answers = Positive#dns_message.answers,
    ?assertMatch([#dns_rr{ttl = 100000}], lists:filter(fun erldns_records:is_soa/1, Answers)),
    ?assertMatch(
        [#dns_rr{ttl = 100000, data = #dns_rrdata_rrsig{original_ttl = 100000}}],
        lists:filter(fun erldns_records:is_soa_rrsig/1, Answers)
    ).

%% ---------------------------------------------------------------------------------------------
%% Delegation points
%%
%% The zone that delegation_zone/0 builds, drawn as a tree. Each name carries what the parent
%% may do with it:
%%
%%   own   the parent's authoritative data: signed, and may own an NSEC
%%   held  stored for the child (the delegation NS RRset, glue): served in referrals, never
%%         signed, never a bit in an NSEC (RFC 4035 §2.2, RFC 4034 §4.1.2)
%%   occl  occluded below a cut: stored, but never served, never signed, never in an NSEC
%%   none  exists nowhere in the parent
%%
%%                              example-delegation.com          own  SOA NS
%%                                        |
%%     +----------+----------+------------+----------+------------------+-----------+
%%     |          |          |                       |                  |           |
%%    ns1      target      alias                  secure            insecure      Mixed
%%   own A     own A    own CNAME                held NS            held NS     held NS
%%                          |                    own  DS            held A (glue at
%%                          |                    held A (glue)      |     the cut)
%%   zone cut ==============|=======================|==================|============|=====
%%   below: the parent is   |                       |                  |            |
%%   not authoritative      +-CNAME-> www.secure    +-- sub.secure     |         x.mixed
%%                                    occl CNAME        occl NS DS CDS |          none
%%                                                            +--------+--------+
%%                                                            |                 |
%%                                                      ns1.insecure   nonexistent.insecure
%%                                                     held A (glue)          none
%%
%% A query for any name at or below a cut gets a referral (RFC 4035 §3.1.4): the NS RRset
%% first and unsigned, then the DS RRset with its RRSIG when the delegation is secure, or the
%% NSEC owned by the delegation name, bitmap NS RRSIG NSEC, when it is not. Nothing in the
%% response is owned by the QNAME, whatever the parent stores there. AD stays clear (§3.1.6).
%% The cut is the topmost one: sub.secure is occluded by secure, and so is everything under it.
%%
%%   A   www.secure           -> NS secure, DS secure, RRSIG DS      (occluded CNAME not shown)
%%   A   www.sub.secure       -> the same: the nested cut is the child's business
%%   NS  secure               -> NS secure, DS secure, RRSIG DS
%%   A   alias                -> CNAME alias + RRSIG, then that referral; no RRSIG over NS
%%   A   ns1.insecure         -> NS insecure, NSEC insecure [NS RRSIG NSEC], RRSIG NSEC
%%   A   nonexistent.insecure -> the same: only the child can deny a name below its cut
%%   DS  ns1.insecure         -> the same: a DS below a cut is the child's to deny
%%   DS  www.secure           -> the referral with DS secure, not the occluded CNAME
%%   DS  sub.secure           -> the same: the DS at the nested cut is occluded
%%   DS  insecure             -> authoritative NODATA: SOA + RRSIG, NSEC insecure
%%                               [NS RRSIG NSEC]; the glue A at insecure stays out of the bitmap
%%   DS  secure               -> authoritative answer: DS + RRSIG DS, signed with the ZSK,
%%                               though the delegation's NS points at secure itself
%%   A   x.mixed              -> NS Mixed as stored; NSEC and RRSIG owned by mixed, the
%%                               lowercased name canonical form requires
%%
%% Zone signing draws the same line: only own data gets an RRSIG. The delegation NS RRsets,
%% the glue A records, www.secure CNAME and the NS, DS and CDS at sub.secure get none; secure
%% DS does. NSECs are never stored: the one at a delegation is signed per query like any other.
%% ---------------------------------------------------------------------------------------------

%% RFC 4035 §3.1.4: a secure delegation is referred to with its DS RRset and RRSIG. No NSEC is
%% derived from the QNAME, so the CNAME occluded below the cut is not disclosed.
referral_below_secure_delegation_carries_ds(_Config) ->
    Zone = put_delegation_zone(),
    Cut = in_zone(~"secure"),
    ZskTag = zsk_tag(Zone),
    #dns_message{aa = false, ad = false, answers = [], authority = Authority} =
        resolve(in_zone(~"www.secure"), ?DNS_TYPE_A),
    ?assertEqual(
        lists:sort([{Cut, ?DNS_TYPE_NS}, {Cut, ?DNS_TYPE_DS}, {Cut, ?DNS_TYPE_RRSIG}]),
        names_and_types(Authority)
    ),
    ?assertMatch(
        #dns_rr{
            name = Cut,
            data = #dns_rrdata_rrsig{
                type_covered = ?DNS_TYPE_DS, keytag = ZskTag, signers_name = ?DELEGATION_ZONE
            }
        },
        lists:keyfind(?DNS_TYPE_RRSIG, #dns_rr.type, Authority)
    ).

%% An insecure delegation is referred to with the NSEC at the delegation name, whose bitmap holds
%% no glue, whether the QNAME is glue below the cut or a name that does not exist there.
referral_below_insecure_delegation_denies_ds_at_the_cut(_Config) ->
    put_delegation_zone(),
    Cut = in_zone(~"insecure"),
    #dns_message{aa = false, answers = [], authority = Authority} =
        resolve(in_zone(~"ns1.insecure"), ?DNS_TYPE_A),
    ?assertEqual(
        lists:sort([{Cut, ?DNS_TYPE_NS}, {Cut, ?DNS_TYPE_NSEC}, {Cut, ?DNS_TYPE_RRSIG}]),
        names_and_types(Authority)
    ),
    ?assertMatch(
        #dns_rr{
            name = Cut,
            data = #dns_rrdata_nsec{types = [?DNS_TYPE_NS, ?DNS_TYPE_RRSIG, ?DNS_TYPE_NSEC]}
        },
        lists:keyfind(?DNS_TYPE_NSEC, #dns_rr.type, Authority)
    ),
    #dns_message{aa = false, answers = [], authority = Authority2} =
        resolve(in_zone(~"nonexistent.insecure"), ?DNS_TYPE_A),
    ?assertEqual(names_and_types(Authority), names_and_types(Authority2)).

ns_query_at_secure_delegation_is_a_referral_with_ds(_Config) ->
    put_delegation_zone(),
    Cut = in_zone(~"secure"),
    #dns_message{aa = false, answers = [], authority = Authority} = resolve(Cut, ?DNS_TYPE_NS),
    ?assertEqual(
        lists:sort([{Cut, ?DNS_TYPE_NS}, {Cut, ?DNS_TYPE_DS}, {Cut, ?DNS_TYPE_RRSIG}]),
        names_and_types(Authority)
    ).

%% RFC 4035 §2.2: the NS RRset at a delegation point is never signed, even on the path where the
%% resolver has already produced answers and the signer looks up signatures for every section.
cname_into_delegation_signs_the_chain_but_not_the_ns(_Config) ->
    put_delegation_zone(),
    Alias = in_zone(~"alias"),
    Cut = in_zone(~"secure"),
    #dns_message{aa = false, answers = Answers, authority = Authority} =
        resolve(Alias, ?DNS_TYPE_A),
    ?assertEqual(
        lists:sort([{Alias, ?DNS_TYPE_CNAME}, {Alias, ?DNS_TYPE_RRSIG}]),
        names_and_types(Answers)
    ),
    ?assertEqual(
        lists:sort([{Cut, ?DNS_TYPE_NS}, {Cut, ?DNS_TYPE_DS}, {Cut, ?DNS_TYPE_RRSIG}]),
        names_and_types(Authority)
    ),
    ?assertMatch(
        [#dns_rr{data = #dns_rrdata_rrsig{type_covered = ?DNS_TYPE_DS}}],
        [RR || #dns_rr{type = ?DNS_TYPE_RRSIG} = RR <- Authority]
    ).

%% A DS query at an insecure delegation is answered authoritatively; the NSEC proving the DS
%% absent must not advertise the glue stored at the delegation name.
nodata_at_insecure_delegation_omits_glue_from_the_nsec(_Config) ->
    put_delegation_zone(),
    Cut = in_zone(~"insecure"),
    #dns_message{aa = true, answers = [], authority = Authority} = resolve(Cut, ?DNS_TYPE_DS),
    ?assert(lists:any(fun erldns_records:is_soa/1, Authority)),
    ?assertMatch(
        #dns_rr{
            name = Cut,
            data = #dns_rrdata_nsec{types = [?DNS_TYPE_NS, ?DNS_TYPE_RRSIG, ?DNS_TYPE_NSEC]}
        },
        lists:keyfind(?DNS_TYPE_NSEC, #dns_rr.type, Authority)
    ).

%% RFC 4035 §3.1.4.1: the DS RRset is the parent's, so a DS query for the delegation name is
%% answered here, also when the delegation's NS points at that very name.
ds_query_at_secure_delegation_is_answered(_Config) ->
    Zone = put_delegation_zone(),
    Cut = in_zone(~"secure"),
    ZskTag = zsk_tag(Zone),
    #dns_message{aa = true, ad = true, answers = Answers, authority = []} =
        resolve(Cut, ?DNS_TYPE_DS),
    ?assertMatch(
        [
            #dns_rr{name = Cut, type = ?DNS_TYPE_DS},
            #dns_rr{
                name = Cut, data = #dns_rrdata_rrsig{type_covered = ?DNS_TYPE_DS, keytag = ZskTag}
            }
        ],
        Answers
    ).

%% A DS below a cut, be it at glue or at an occluded nested cut, is the child's to deny: the
%% answer is the referral, not a denial signed by the parent over what it happens to store there.
ds_query_below_a_cut_is_a_referral(_Config) ->
    put_delegation_zone(),
    Insecure = in_zone(~"insecure"),
    Secure = in_zone(~"secure"),
    #dns_message{aa = false, ad = false, answers = [], authority = Authority1} =
        resolve(in_zone(~"ns1.insecure"), ?DNS_TYPE_DS),
    ?assertEqual(
        lists:sort([
            {Insecure, ?DNS_TYPE_NS}, {Insecure, ?DNS_TYPE_NSEC}, {Insecure, ?DNS_TYPE_RRSIG}
        ]),
        names_and_types(Authority1)
    ),
    #dns_message{aa = false, answers = [], authority = Authority2} =
        resolve(in_zone(~"www.secure"), ?DNS_TYPE_DS),
    ?assertEqual(
        lists:sort([{Secure, ?DNS_TYPE_NS}, {Secure, ?DNS_TYPE_DS}, {Secure, ?DNS_TYPE_RRSIG}]),
        names_and_types(Authority2)
    ),
    #dns_message{aa = false, answers = [], authority = Authority3} =
        resolve(in_zone(~"sub.secure"), ?DNS_TYPE_DS),
    ?assertEqual(names_and_types(Authority2), names_and_types(Authority3)).

%% A cut under another cut is occluded by it: the referral names the topmost delegation and
%% carries its DS, whatever the parent stores deeper down.
nested_cut_refers_to_the_topmost_delegation(_Config) ->
    put_delegation_zone(),
    Cut = in_zone(~"secure"),
    #dns_message{aa = false, answers = [], authority = Authority} =
        resolve(in_zone(~"www.sub.secure"), ?DNS_TYPE_A),
    ?assertEqual(
        lists:sort([{Cut, ?DNS_TYPE_NS}, {Cut, ?DNS_TYPE_DS}, {Cut, ?DNS_TYPE_RRSIG}]),
        names_and_types(Authority)
    ).

%% RFC 4034 §6.1: the NSEC and its RRSIG are owned by the delegation name in canonical, that is
%% lowercased, form, while the NS RRset is served as stored.
delegation_proof_is_owned_by_the_lowercased_name(_Config) ->
    put_delegation_zone(),
    Stored = in_zone(~"Mixed"),
    Cut = in_zone(~"mixed"),
    Next = <<0, ".", Cut/binary>>,
    #dns_message{aa = false, answers = [], authority = Authority} =
        resolve(in_zone(~"x.mixed"), ?DNS_TYPE_A),
    ?assertEqual(
        lists:sort([{Stored, ?DNS_TYPE_NS}, {Cut, ?DNS_TYPE_NSEC}, {Cut, ?DNS_TYPE_RRSIG}]),
        names_and_types(Authority)
    ),
    ?assertMatch(
        #dns_rr{data = #dns_rrdata_nsec{next_dname = Next}},
        lists:keyfind(?DNS_TYPE_NSEC, #dns_rr.type, Authority)
    ).

%% The request's own answer and authority sections take no part: neither in what is signed nor
%% in what the response is taken to refer to.
sections_of_the_request_are_dropped(_Config) ->
    put_delegation_zone(),
    Target = in_zone(~"target"),
    Cut = in_zone(~"secure"),
    Planted = #dns_rr{
        name = Target,
        type = ?DNS_TYPE_NS,
        ttl = 1,
        data = #dns_rrdata_ns{dname = ~"ns.attacker.example"}
    },
    #dns_message{aa = true, answers = Answers, authority = []} =
        resolve(Target, ?DNS_TYPE_A, [Planted]),
    ?assertEqual(
        lists:sort([{Target, ?DNS_TYPE_A}, {Target, ?DNS_TYPE_RRSIG}]), names_and_types(Answers)
    ),
    #dns_message{aa = false, answers = [], authority = Authority} =
        resolve(in_zone(~"www.secure"), ?DNS_TYPE_A, [Planted]),
    ?assertEqual(
        lists:sort([{Cut, ?DNS_TYPE_NS}, {Cut, ?DNS_TYPE_DS}, {Cut, ?DNS_TYPE_RRSIG}]),
        names_and_types(Authority)
    ).

%% An error from the resolver denies nothing: it goes out as it is, AD clear and unsigned.
error_from_the_resolver_is_left_alone(_Config) ->
    Zone = put_delegation_zone(),
    QName = in_zone(~"target"),
    QLabels = dns_domain:split(QName),
    Msg = #dns_message{
        qc = 1,
        aa = false,
        rc = ?DNS_RCODE_SERVFAIL,
        questions = [#dns_query{name = QName, type = ?DNS_TYPE_A}],
        additional = [#dns_optrr{dnssec = true}]
    },
    ?assertEqual(
        Msg, erldns_dnssec:handle(Msg, Zone, QLabels, QName, ?DNS_TYPE_A, none, #{}, true)
    ).

%% RFC 4035 §2.2: an RRSIG carries the TTL of the RRset it covers. The NSEC of a delegation takes
%% the zone's negative TTL and is signed when served, so an SOA update reaches both at once.
delegation_nsec_ttl_follows_the_soa(_Config) ->
    Zone = put_delegation_zone(),
    [Soa] = [RR || #dns_rr{type = ?DNS_TYPE_SOA} = RR <- Zone#zone.records],
    Data = Soa#dns_rr.data,
    Soa2 = Soa#dns_rr{data = Data#dns_rrdata_soa{serial = 2, minimum = 600}},
    ok = erldns_zone_cache:put_zone_rrset(
        {?DELEGATION_ZONE, ~"2", [Soa2]}, ?DELEGATION_ZONE, ?DNS_TYPE_SOA, 1
    ),
    #dns_message{authority = Authority} = resolve(in_zone(~"ns1.insecure"), ?DNS_TYPE_A),
    [Nsec] = [RR || #dns_rr{type = ?DNS_TYPE_NSEC} = RR <- Authority],
    [Sig] = [
        RR
     || #dns_rr{data = #dns_rrdata_rrsig{type_covered = ?DNS_TYPE_NSEC}} = RR <- Authority
    ],
    ?assertEqual(600, Nsec#dns_rr.ttl),
    ?assertEqual(600, Sig#dns_rr.ttl),
    ?assertEqual(600, Sig#dns_rr.data#dns_rrdata_rrsig.original_ttl).

zone_signing_skips_delegation_ns_glue_and_occluded_records(_Config) ->
    Zone = delegation_zone(),
    ZskTag = zsk_tag(Zone),
    #{zone_rrsig_rrs := ZoneSigs, key_rrsig_rrs := KeySigs} = erldns_dnssec:get_signed_records(
        Zone
    ),
    %% The CDS at sub.secure is occluded like everything else below the cut.
    ?assertEqual([], KeySigs),
    ?assertEqual(
        lists:sort([
            {?DELEGATION_ZONE, ?DNS_TYPE_SOA},
            {?DELEGATION_ZONE, ?DNS_TYPE_NS},
            {in_zone(~"ns1"), ?DNS_TYPE_A},
            {in_zone(~"target"), ?DNS_TYPE_A},
            {in_zone(~"alias"), ?DNS_TYPE_CNAME},
            {in_zone(~"secure"), ?DNS_TYPE_DS}
        ]),
        names_and_types_covered(ZoneSigs)
    ),
    ?assertMatch(
        [#dns_rr{data = #dns_rrdata_rrsig{keytag = ZskTag}}],
        [RR || #dns_rr{data = #dns_rrdata_rrsig{type_covered = ?DNS_TYPE_DS}} = RR <- ZoneSigs]
    ).

%% An RRset arriving on its own is placed against the cuts the cache holds, so glue and occluded
%% data added later stay unsigned too, and a new delegation is recognised by its own NS RRset.
rrset_signing_skips_delegation_ns_and_signs_ds(_Config) ->
    Zone = put_delegation_zone(),
    ZskTag = zsk_tag(Zone),
    RRSet = fun(Name, Type) ->
        [RR || #dns_rr{name = N, type = T} = RR <- Zone#zone.records, N =:= Name, T =:= Type]
    end,
    Sign = fun(Records) -> erldns_dnssec:get_signed_zone_records(Zone#zone{records = Records}) end,
    NewCut = #dns_rr{
        name = in_zone(~"fresh"),
        type = ?DNS_TYPE_NS,
        ttl = 3600,
        data = #dns_rrdata_ns{dname = ~"ns1.other.example"}
    },
    ?assertEqual([], Sign(RRSet(in_zone(~"secure"), ?DNS_TYPE_NS))),
    ?assertEqual([], Sign(RRSet(in_zone(~"secure"), ?DNS_TYPE_A))),
    ?assertEqual([], Sign(RRSet(in_zone(~"ns1.insecure"), ?DNS_TYPE_A))),
    ?assertEqual([], Sign(RRSet(in_zone(~"www.secure"), ?DNS_TYPE_CNAME))),
    ?assertEqual([], Sign(RRSet(in_zone(~"sub.secure"), ?DNS_TYPE_DS))),
    ?assertEqual([], Sign([NewCut])),
    ?assertMatch(
        [#dns_rr{data = #dns_rrdata_rrsig{type_covered = ?DNS_TYPE_DS, keytag = ZskTag}}],
        Sign(RRSet(in_zone(~"secure"), ?DNS_TYPE_DS))
    ),
    ?assertMatch(
        [#dns_rr{data = #dns_rrdata_rrsig{type_covered = ?DNS_TYPE_NS}}],
        Sign(RRSet(?DELEGATION_ZONE, ?DNS_TYPE_NS))
    ).

%% Run a question through the resolver and the signer pipes, as the pipeline would.
resolve(QName, QType) ->
    resolve(QName, QType, []).

%% The same, with records the request carries in its authority section.
resolve(QName, QType, RequestAuthority) ->
    QLabels = dns_domain:split(QName),
    Msg0 = #dns_message{
        qc = 1,
        questions = [#dns_query{name = QName, type = QType}],
        authority = RequestAuthority,
        additional = [#dns_optrr{dnssec = true}]
    },
    Opts0 = erldns_dnssec:prepare(
        erldns_resolver:prepare(#{
            resolved => false, query_name => QName, query_labels => QLabels, query_type => QType
        })
    ),
    {Msg1, Opts1} = erldns_resolver:call(Msg0, Opts0),
    {Msg2, _} = erldns_dnssec:call(Msg1, Opts1),
    Msg2.

put_delegation_zone() ->
    Zone = delegation_zone(),
    ok = erldns_zone_cache:put_zone(Zone),
    Zone.

%% The zone drawn at the top of this section: a secure delegation whose name server sits at the
%% cut itself, hiding a CNAME and a further cut below it; an insecure one, served the same way,
%% with glue at and below its cut; and an insecure one stored with a capital letter. Signed with
%% the keys of example-dnssec0.com from the suite's zone file.
delegation_zone() ->
    #zone{keysets = Keysets} =
        erldns_zone_cache:get_authoritative_zone(dns_domain:split(~"example-dnssec0.com")),
    RR = fun(Name, Type, Data) -> #dns_rr{name = Name, type = Type, ttl = 3600, data = Data} end,
    Digest = binary:decode_hex(~"a0b9c38cd324182af0ef66830d0a0e85a1d58979c9834e18c871779e040857b7"),
    Records = [
        RR(?DELEGATION_ZONE, ?DNS_TYPE_SOA, #dns_rrdata_soa{
            mname = in_zone(~"ns1"),
            rname = in_zone(~"hostmaster"),
            serial = 1,
            refresh = 3600,
            retry = 600,
            expire = 604800,
            minimum = 300
        }),
        RR(?DELEGATION_ZONE, ?DNS_TYPE_NS, #dns_rrdata_ns{dname = in_zone(~"ns1")}),
        RR(in_zone(~"ns1"), ?DNS_TYPE_A, #dns_rrdata_a{ip = {192, 0, 2, 53}}),
        RR(in_zone(~"target"), ?DNS_TYPE_A, #dns_rrdata_a{ip = {192, 0, 2, 10}}),
        RR(in_zone(~"alias"), ?DNS_TYPE_CNAME, #dns_rrdata_cname{dname = in_zone(~"www.secure")}),
        RR(in_zone(~"secure"), ?DNS_TYPE_NS, #dns_rrdata_ns{dname = in_zone(~"secure")}),
        RR(in_zone(~"secure"), ?DNS_TYPE_A, #dns_rrdata_a{ip = {192, 0, 2, 98}}),
        RR(in_zone(~"secure"), ?DNS_TYPE_DS, #dns_rrdata_ds{
            keytag = 46096, alg = 8, digest_type = 2, digest = Digest
        }),
        RR(in_zone(~"www.secure"), ?DNS_TYPE_CNAME, #dns_rrdata_cname{dname = in_zone(~"target")}),
        RR(in_zone(~"sub.secure"), ?DNS_TYPE_NS, #dns_rrdata_ns{dname = ~"ns1.other.example"}),
        RR(in_zone(~"sub.secure"), ?DNS_TYPE_DS, #dns_rrdata_ds{
            keytag = 46096, alg = 8, digest_type = 2, digest = Digest
        }),
        RR(in_zone(~"sub.secure"), ?DNS_TYPE_CDS, #dns_rrdata_cds{
            keytag = 46096, alg = 8, digest_type = 2, digest = Digest
        }),
        RR(in_zone(~"insecure"), ?DNS_TYPE_NS, #dns_rrdata_ns{dname = in_zone(~"insecure")}),
        RR(in_zone(~"insecure"), ?DNS_TYPE_A, #dns_rrdata_a{ip = {192, 0, 2, 99}}),
        RR(in_zone(~"ns1.insecure"), ?DNS_TYPE_A, #dns_rrdata_a{ip = {192, 0, 2, 100}}),
        RR(in_zone(~"Mixed"), ?DNS_TYPE_NS, #dns_rrdata_ns{dname = ~"ns1.other.example"})
    ],
    erldns_zone_codec:build_zone(?DELEGATION_ZONE, ~"1", Records, Keysets).

in_zone(Prefix) ->
    <<Prefix/binary, ".", ?DELEGATION_ZONE/binary>>.

zsk_tag(#zone{keysets = [#keyset{zone_signing_key_tag = Tag} | _]}) ->
    Tag.

names_and_types(RRs) ->
    lists:sort([{Name, Type} || #dns_rr{name = Name, type = Type} <- RRs]).

names_and_types_covered(RRSigs) ->
    lists:sort([
        {Name, Covered}
     || #dns_rr{name = Name, data = #dns_rrdata_rrsig{type_covered = Covered}} <- RRSigs
    ]).
