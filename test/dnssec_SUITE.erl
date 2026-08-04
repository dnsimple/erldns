-module(dnssec_SUITE).
-compile([export_all, nowarn_export_all]).

-behaviour(ct_suite).

-include_lib("stdlib/include/assert.hrl").
-include_lib("dns_erlang/include/dns.hrl").
-include_lib("erldns/include/erldns.hrl").

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
        nsec_signed_for_max_length_qname
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
        erldns_dnssec:handle(Msg0, Zone, QLabels, QName, QType, #{}, true),
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
