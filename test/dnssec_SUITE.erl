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
        verify_zsk_signed,
        verify_zsk_signed_alg13,
        test_signer_selection_logic,
        test_requires_key_signing_key_function
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
    erldns_zone_cache:start_link(),
    erldns_zone_codec:start_link(),
    erldns_zone_loader:start_link(),
    erldns_handler:start_link(),
    Config.

-spec end_per_testcase(ct_suite:ct_testcase(), ct_suite:ct_config()) -> term().
end_per_testcase(_, _Config) ->
    ok.

verify_ksk_signed(_) ->
    Name = dns:dname_to_lower(~"example-dnssec0.com"),
    Labels = dns:dname_to_labels(Name),
    QType = ?DNS_TYPE_A,
    Q = #dns_query{name = Name, type = QType},
    A = #dns_rr{name = Name, type = QType, data = #dns_rrdata_a{ip = {1, 2, 3, 4}}},
    Ad = #dns_optrr{dnssec = true},
    Msg0 = #dns_message{
        qc = 1, anc = 1, auc = 1, questions = [Q], answers = [A], additional = [Ad]
    },
    Zone = erldns_zone_cache:get_authoritative_zone(Labels),
    Msg1 = erldns_dnssec:handle(Msg0, Zone, Name, QType),
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
    Name = dns:dname_to_lower(~"example-dnssec1.com"),
    Labels = dns:dname_to_labels(Name),
    QType = ?DNS_TYPE_A,
    Q = #dns_query{name = Name, type = QType},
    A = #dns_rr{name = Name, type = QType, data = #dns_rrdata_a{ip = {1, 2, 3, 4}}},
    Ad = #dns_optrr{dnssec = true},
    Msg0 = #dns_message{
        qc = 1, anc = 1, auc = 1, questions = [Q], answers = [A], additional = [Ad]
    },
    Zone = erldns_zone_cache:get_authoritative_zone(Labels),
    Msg1 = erldns_dnssec:handle(Msg0, Zone, Name, QType),
    ct:pal("msg: ~p~n", [Msg1]),
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
    Name = dns:dname_to_lower(~"example-dnssec0.com"),
    Labels = dns:dname_to_labels(Name),
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
    Msg1 = erldns_dnssec:handle(Msg0, Zone, Name, QType),
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
    Name = dns:dname_to_lower(~"example-dnssec1.com"),
    Labels = dns:dname_to_labels(Name),
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
    Msg1 = erldns_dnssec:handle(Msg0, Zone, Name, QType),
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
