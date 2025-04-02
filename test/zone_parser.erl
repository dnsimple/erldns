-module(zone_parser).
-compile([export_all, nowarn_export_all]).

-include_lib("dns_erlang/include/dns.hrl").
-include_lib("eunit/include/eunit.hrl").

json_to_erlang_test() ->
    R = erldns_zone_parser:json_to_erlang(json:decode(input()), []),
    ?assertMatch({_, _, _, _}, R).

json_to_erlang_txt_spf_records_test() ->
    I = """
    {
      "name": "example.com",
      "records": [
        {
          "context": [],
          "data": {
            "txt": "this is a test",
            "txts": null
          },
          "name": "example.com",
          "ttl": 3600,
          "type": "TXT"
        },
        {
          "context": [],
          "data": {
            "spf": "v=spf1 a mx ~all",
            "txts": null
          },
          "name": "example.com",
          "ttl": 3600,
          "type": "SPF"
        }
      ],
      "sha": "10ea56ad7be9d3e6e75be3a15ef0dfabe9facafba486d74914e7baf8fb36638e"
    }
    """,
    Json = json:decode(iolist_to_binary(I)),
    R = erldns_zone_parser:json_to_erlang(Json, []),
    Expected = [
        #dns_rr{
            name = <<"example.com">>,
            type = 16,
            class = 1,
            ttl = 3600,
            data = #dns_rrdata_txt{txt = [<<"this is a test">>]}
        },
        #dns_rr{
            name = <<"example.com">>,
            type = 99,
            class = 1,
            ttl = 3600,
            data = #dns_rrdata_spf{spf = [<<"v=spf1 a mx ~all">>]}
        }
    ],
    ?assertMatch({<<"example.com">>, Sha, Expected, []} when is_binary(Sha), R).

json_to_erlang_ensure_sorting_and_defaults_test() ->
    ?assertEqual({"foo.org", [], [], []}, erldns_zone_parser:json_to_erlang([{<<"name">>, "foo.org"}, {<<"records">>, []}], [])).

json_record_to_erlang_test() ->
    erldns_events:start_link(),
    ?assertEqual({}, erldns_zone_parser:json_record_to_erlang([])),
    Name = <<"example.com">>,
    ?assertEqual({}, erldns_zone_parser:json_record_to_erlang([Name, <<"SOA">>, 3600, null, null])).

json_record_soa_to_erlang_test() ->
    Name = <<"example.com">>,
    ?assertEqual(
        #dns_rr{
            name = Name,
            type = ?DNS_TYPE_SOA,
            data =
                #dns_rrdata_soa{
                    mname = <<"ns1.example.com">>,
                    rname = <<"admin.example.com">>,
                    serial = 12345,
                    refresh = 555,
                    retry = 666,
                    expire = 777,
                    minimum = 888
                },
            ttl = 3600
        },
        erldns_zone_parser:json_record_to_erlang([
            Name,
            <<"SOA">>,
            3600,
            [
                {<<"mname">>, <<"ns1.example.com">>},
                {<<"rname">>, <<"admin.example.com">>},
                {<<"serial">>, 12345},
                {<<"refresh">>, 555},
                {<<"retry">>, 666},
                {<<"expire">>, 777},
                {<<"minimum">>, 888}
            ],
            undefined
        ])
    ).

json_record_ns_to_erlang_test() ->
    Name = <<"example.com">>,
    ?assertEqual(
        #dns_rr{
            name = Name,
            type = ?DNS_TYPE_NS,
            data = #dns_rrdata_ns{dname = <<"ns1.example.com">>},
            ttl = 3600
        },
        erldns_zone_parser:json_record_to_erlang([Name, <<"NS">>, 3600, [{<<"dname">>, <<"ns1.example.com">>}], undefined])
    ).

json_record_a_to_erlang_test() ->
    Name = <<"example.com">>,
    ?assertEqual(
        #dns_rr{
            name = Name,
            type = ?DNS_TYPE_A,
            data = #dns_rrdata_a{ip = {1, 2, 3, 4}},
            ttl = 3600
        },
        erldns_zone_parser:json_record_to_erlang([Name, <<"A">>, 3600, [{<<"ip">>, <<"1.2.3.4">>}], undefined])
    ).

json_record_aaaa_to_erlang_test() ->
    Name = <<"example.com">>,
    ?assertEqual(
        #dns_rr{
            name = Name,
            type = ?DNS_TYPE_AAAA,
            data = #dns_rrdata_aaaa{ip = {0, 0, 0, 0, 0, 0, 0, 1}},
            ttl = 3600
        },
        erldns_zone_parser:json_record_to_erlang([Name, <<"AAAA">>, 3600, [{<<"ip">>, <<"::1">>}], undefined])
    ).

json_record_cds_to_erlang_test() ->
    Name = <<"example-dnssec.com">>,
    ?assertEqual(
        #dns_rr{
            name = Name,
            type = ?DNS_TYPE_CDS,
            data =
                #dns_rrdata_cds{
                    keytag = 0,
                    digest_type = 2,
                    alg = 8,
                    digest = binary:decode_hex(<<"4315A7AD09AE0BEBA6CC3104BBCD88000ED796887F1C4D520A3A608D715B72CA">>)
                },
            ttl = 3600
        },
        erldns_zone_parser:json_record_to_erlang([
            Name,
            <<"CDS">>,
            3600,
            [
                {<<"keytag">>, 0},
                {<<"digest_type">>, 2},
                {<<"alg">>, 8},
                {<<"digest">>, <<"4315A7AD09AE0BEBA6CC3104BBCD88000ED796887F1C4D520A3A608D715B72CA">>}
            ],
            undefined
        ])
    ).

parse_json_keys_unsorted_proplists_test() ->
    ?assertEqual(
        [
            {keyset,
                [
                    1025,
                    117942195211355436516708579275854541924575773884167758398377054474457061084450782563901956510831117716183526402173215071572529228555976594387632086643427143744605045813923857147839015187463121492324352653506190767692034127161982651669657643423469824721891177589201529187860925827553628207715191151413138514807,
                    105745246243156727959858716443424706369448913365414799968886354206854672328400262610952095642393948469436742208387497220268443279066285356333886719634448317208189715942402022382731037836531762881862458283240610274107136766709456566004076449761688996028612988763775001691587086168632010166111722279727494037097
                ],
                37440, 8,
                [
                    513,
                    9170529505818457214552347052832728824507861128011245996056627438339703762731346681703094163316286362641501571794424157931806097889892946273849538579240359,
                    5130491166023191463112131781994138738077497356216817935415696052248528225933414267440640871636073852185344964288812312263453467652493907737029964715172561
                ],
                49016, 8, {{2016, 11, 14}, {11, 36, 58}}, {{2017, 2, 12}, {11, 36, 58}}}
        ],
        erldns_zone_parser:parse_json_keys([
            [
                {<<"ksk">>, <<
                    "-----BEGIN RSA PRIVATE KEY-----\nMIICXAIBAAKBgQCn9Iv82vkFiv8ts8K9jzUzfp3UEZx+76r+X9A4GOFfYbx3USCh\nEW0fLYT/Q"
                    "kAM8/SiTkEXzZPqhrV083mp5VLYNLxic2ii6DrwvyGpENVPJnDQMu+C\nfKMyb9IWcm9MkeHh8t/ovsCQAEJWIPTnzv8rlQcDU44c3qgTpHS"
                    "U8htjdwICBAEC\ngYEAlpYTHWYrcd0HQXO3F9lPqwwfHUt7VBaSEUYrk3N3ZYCWvmV1qyKbB/kb1SBs\n4GfW1vP966HXCffnX92LDXYxi7I"
                    "t3TJaKmo8aF/leN7w8WLNJXUayEoQKUfKLprj\nN14Jx/tgMu7I/BOoHId8b7e57pBKtDiSF6WWn3K7tNPbfmkCQQDST41m62mC4MAa\nDsU"
                    "dyM0Vg/tjduGqnygryCDEXDabdg95a3wMk0SQCQzZFHGNYnsXcffTqGs/y+5w\nQWxyOGSNAkEAzHFkDJla30NiiKvhu7dY+0+dGrfMA7pNU"
                    "h+LGdXe5QFdjwwxqPbF\n7NMGXKMdB8agSCxGZC3bxdvYNF9LULzhEwJABpDYNSoQx+UMvaEN5XTpLmCHuS1r\nsmhfKZPcDx8Z7mAYda3wZ"
                    "EuHQq+cf6i5XhOO9P5QKpKeslHLAMHa7NaNgQJBAI03\nGGacYLwui32fbzb8BYRg82Kga/OW6btY+O6hNs6iSR2gBlQ9j3Tgrzo+N4R/NQS"
                    "l\nc05wGO2RnBUwlu0XUckCQHfHsWHVrrADTpalbv+FTDyWd0ouHXBmDecVZh3e7/ue\ncdMoblzeasvgp8CjFa9U+uDozY+aL6TNIpG++nn"
                    "4lNw=\n-----END RSA PRIVATE KEY-----\n"
                >>},
                {<<"ksk_alg">>, 8},
                {<<"ksk_keytag">>, 37440},
                {<<"zsk">>, <<
                    "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK8YnU+YqBxD/EDwVeHZsJillAJ80PCnLU+/rlGrlzgw+eabF8jT\nCaEwnpE74"
                    "YHCLegKAAn+efeZrT/EBBrzlacCAgIBAkBh9VGFW2SJk1I9SBQaDIA9\nchdrrx+PHibSyozwT4eAPmd6OFoLausc7ls6v9evPeb+Yj3g0JX"
                    "vTGp6BgNhFqLR\nAiEA1+ievAEBVM6IlOmpiTwlaWe/HV6MokBBq1G/tvJS0M8CIQDPm/DUsoTEv/Jj\n6O3U9hNcPLbvKMMGld2wbf7nrQm"
                    "zqQIhAJrhwTaFdjnXhmfUB9a33vRIbSaIsLxA\nDyuM+03XP+YhAiEAmJIJz7WX9uPkCIy8wO655Hh4dt4UkBFRE98OqkHIwGkCIFFv\nN8r"
                    "JojI+oEiJyNjEjWZD4qoUMUp3+YBl0htAJUE2\n-----END RSA PRIVATE KEY-----\n"
                >>},
                {<<"zsk_alg">>, 8},
                {<<"zsk_keytag">>, 49016},
                {<<"inception">>, <<"2016-11-14T11:36:58.851612Z">>},
                {<<"until">>, <<"2017-02-12T11:36:58.849384Z">>}
            ]
        ])
    ).

hex_to_bin_test() ->
    ?assertEqual(<<"">>, binary:decode_hex(<<"">>)),
    ?assertEqual(<<255, 0, 255>>, binary:decode_hex(<<"FF00FF">>)).

base64_to_bin_test() ->
    ?assertEqual(<<"">>, base64:decode(<<"">>)),
    ?assertEqual(
        <<3, 1, 0, 1, 191, 165, 76, 56, 217, 9, 250, 187, 15, 147, 125, 112, 215, 117, 186, 13, 244, 192, 186, 219, 9, 112, 125, 153, 82,
            73, 64, 105, 80, 64, 122, 98, 28, 121, 76, 104, 177, 134, 177, 93, 191, 143, 159, 158, 162, 49, 233, 249, 100, 20, 204, 218, 78,
            206, 181, 11, 23, 169, 172, 108, 75, 212, 185, 93, 160, 72, 73, 233, 110, 231, 145, 87, 139, 112, 59, 201, 174, 24, 79, 177,
            121, 75, 172, 121, 42, 7, 135, 246, 147, 164, 15, 25, 245, 35, 238, 109, 189, 53, 153, 219, 170, 169, 165, 4, 55, 146, 110, 207,
            100, 56, 132, 93, 29, 73, 68, 137, 98, 82, 79, 42, 26, 122, 54, 179, 160, 161, 236, 163>>,
        base64:decode(<<
            "AwEAAb+lTDjZCfq7D5N9cNd1ug30wLrbCXB9mVJJQGlQQHpiHHlMaLGGsV2/j5+eojHp+WQUzNpOzrULF6msbEvUuV2gSEnpbueRV4twO8mu"
            "GE+xeUuseSoHh/aTpA8Z9SPubb01mduqqaUEN5Juz2Q4hF0dSUSJYlJPKhp6NrOgoeyj"
        >>)
    ).

input() ->
    I = """
    {
      "name": "example.com",
      "records": [
        {
          "context": [
            "anycast"
          ],
          "data": {
            "expire": 604800,
            "minimum": 300,
            "mname": "ns1.dnsimple.com",
            "refresh": 86400,
            "retry": 7200,
            "rname": "admin.dnsimple.com",
            "serial": 1597990915
          },
          "name": "example.com",
          "ttl": 3600,
          "type": "SOA"
        },
        {
          "context": [
            "anycast"
          ],
          "data": { "dname": "ns1.dnsimple.com" },
          "name": "example.com",
          "ttl": 3600,
          "type": "NS"
        },
        {
          "context": [
            "anycast"
          ],
          "data": { "dname": "ns2.dnsimple.com" },
          "name": "example.com",
          "ttl": 3600,
          "type": "NS"
        },
        {
          "context": [
            "anycast"
          ],
          "data": { "dname": "ns3.dnsimple.com" },
          "name": "example.com",
          "ttl": 3600,
          "type": "NS"
        },
        {
          "context": [
            "anycast"
          ],
          "data": { "dname": "ns4.dnsimple.com" },
          "name": "example.com",
          "ttl": 3600,
          "type": "NS"
        },
        {
          "context": [],
          "data": { "ip": "5.4.3.2" },
          "name": "*.qa.example.com",
          "ttl": 3600,
          "type": "A"
        },
        {
          "context": [],
          "data": { "ip": "1.2.3.4" },
          "name": "example.com",
          "ttl": 3600,
          "type": "A"
        },
        {
          "context": [],
          "data": { "ip": "2001:db8:0:0:0:0:2:1" },
          "name": "example.com",
          "ttl": 3600,
          "type": "AAAA"
        },
        {
          "context": [],
          "data": { "dname": "example.com" },
          "name": "www.example.com",
          "ttl": 3600,
          "type": "CNAME"
        },
        {
          "context": [],
          "data": {
            "flags": 0,
            "tag": "issue",
            "value": "comodoca.com"
          },
          "name": "example.com",
          "ttl": 3600,
          "type": "CAA"
        },
        {
          "context": [],
          "data": {
            "exchange": "mailserver.foo.com",
            "preference": 10
          },
          "name": "example.com",
          "ttl": 3600,
          "type": "MX"
        },
        {
          "context": [],
          "data": {
            "txt": "this is a test",
            "txts": null
          },
          "name": "example.com",
          "ttl": 3600,
          "type": "TXT"
        },
        {
          "context": [],
          "data": {
            "spf": "v=spf1 a mx ~all",
            "txts": null
          },
          "name": "example.com",
          "ttl": 3600,
          "type": "SPF"
        },
        {
          "context": [],
          "data": { "txt": "v=spf1 a mx ~all" },
          "name": "example.com",
          "ttl": 3600,
          "type": "TXT"
        },
        {
          "context": [],
          "data": {
            "alg": 3,
            "fp": "ABC123",
            "fptype": 2
          },
          "name": "example.com",
          "ttl": 3600,
          "type": "SSHFP"
        },
        {
          "context": [],
          "data": {
            "port": 3333,
            "priority": 20,
            "target": "example.net",
            "weight": 10
          },
          "name": "_foo._bar.example.com",
          "ttl": 3600,
          "type": "SRV"
        },
        {
          "context": [],
          "data": {
            "flags": "u",
            "order": 5,
            "preference": 10,
            "regexp": "https://example\\.net",
            "replacement": "example.org",
            "services": "foo"
          },
          "name": "example.com",
          "ttl": 3600,
          "type": "NAPTR"
        },
        {
          "context": [
            "SV1"
          ],
          "data": { "ip": "5.5.5.5" },
          "name": "example.com",
          "ttl": 3600,
          "type": "A"
        },
        {
          "context": [],
          "data": {
            "cpu": "cpu",
            "os": "os"
          },
          "name": "example.com",
          "ttl": 3600,
          "type": "HINFO"
        },
        {
          "context": [],
          "data": {
            "alg": 8,
            "flags": 257,
            "key_tag": 0,
            "protocol": 3,
            "public_key": "AwEAAcFwY/oPw5JPGTT2qf2opNMpNAopxC6xWvGO2QAKA7ERAzKYsiXt7j1/ttJjgnLS2Qj30bbnRyazj7Lg9oZcmiJ4/cfBHLBczzaxtqwZrxX1rcQz1OpU/hnq4W5Rsk2i1hxdpRjLnVfddVFD3GDDgIEjvaiKtaJcA61WtDDA08Ba90S7czkUh2Nfv7cTYEFhjnx0bdtapwRQEirHjzyAJqs="
          },
          "name": "example.com",
          "ttl": 3600,
          "type": "DNSKEY"
        },
        {
          "context": [],
          "data": {
            "alg": 8,
            "flags": 256,
            "key_tag": 0,
            "protocol": 3,
            "public_key": "AwEAAddpSYg8TvfhxHRTG1zrCPXWuG/gN0/q2dzQtM3um6zVl0sIFQKWfcdcowpim13K4euSqzltBB+XwDjv9fbWb6x i0mTF0c0NgOQ/Ctf5sQOBtGBkopbQgxDuXDTC1jJaUTVlzjN9m8KYoVacTbhMFBAtwn6LC1sEYfwiCsADk3cV"
          },
          "name": "example.com",
          "ttl": 3600,
          "type": "DNSKEY"
        },
        {
          "context": [],
          "data": {
            "alg": 8,
            "flags": 257,
            "key_tag": 0,
            "protocol": 3,
            "public_key": "AwEAAbPhmoznnzWMbx0h+RcyI+Bi2tzlOnd/AbZK7iXgGY62lZo442+6TpZNlkeFEqk+YKxUce70RWkG/LHuJeywfmPySSra2rYG3P3ntAgbcrbwMDa9cmYVEnS2+ObEFeqowcoe4kjzy5249skMn9Hl8D5pWXp0EbzOSuKSRDFEaGfNycvc8/VfcEi8LwUffTkq8ZFE9P6QEqyeDM4yO2XmoSs="
          },
          "name": "example.com",
          "ttl": 3600,
          "type": "DNSKEY"
        },
        {
          "context": [],
          "data": {
            "alg": 8,
            "flags": 256,
            "key_tag": 0,
            "protocol": 3,
            "public_key": "AwEAAdAKvoBtIj2GzLpawDNm/ztuuxIbU2lticK5lMwisLN8HY1QXjdFk+pOCHp1XsS2Odd6rQyy/IJvBEFFeeZDoyUeoa2i93STTETMZZ/dX1YtJPQnw8MJ0buxfeCxZGRVmbpu4p+YeZ2AFN1ZSziKD7HununBWFXQc7vHRK0QSBTH"
          },
          "name": "example.com",
          "ttl": 3600,
          "type": "DNSKEY"
        },
        {
          "context": [],
          "data": {
            "alg": 8,
            "flags": 257,
            "key_tag": 0,
            "protocol": 3,
            "public_key": "AwEAAbPhmoznnzWMbx0h+RcyI+Bi2tzlOnd/AbZK7iXgGY62lZo442+6TpZNlkeFEqk+YKxUce70RWkG/LHuJeywfmPySSra2rYG3P3ntAgbcrbwMDa9cmYVEnS2+ObEFeqowcoe4kjzy5249skMn9Hl8D5pWXp0EbzOSuKSRDFEaGfNycvc8/VfcEi8LwUffTkq8ZFE9P6QEqyeDM4yO2XmoSs="
          },
          "name": "example.com",
          "ttl": 3600,
          "type": "CDNSKEY"
        },
        {
          "context": [],
          "data": {
            "alg": 8,
            "digest": "933FE542B3351226B7D0460EBFCB3D48909106B052E803E04063ACC179D3664B",
            "digest_type": 2,
            "flags": 61079,
            "keytag": 0
          },
          "name": "example.com",
          "ttl": 3600,
          "type": "CDS"
        }
      ],
      "keys": [
        {
          "inception": "2020-12-02T08:38:09.631363Z",
          "ksk": "-----BEGIN RSA PRIVATE KEY-----\nMIIC7AIBAAKBoQDBcGP6D8OSTxk09qn9qKTTKTQKKcQusVrxjtkACgOxEQMymLIl\n7e49f7bSY4Jy0tkI99G250cms4+y4PaGXJoieP3HwRywXM82sbasGa8V9a3EM9Tq\nVP4Z6uFuUbJNotYcXaUYy51X3XVRQ9xgw4CBI72oirWiXAOtVrQwwNPAWvdEu3M5\nFIdjX7+3E2BBYY58dG3bWqcEUBIqx488gCarAgMBAAECgaBZk/9oVJZ/kYudwEB2\nS/uQIbuMnUzRRqZTyI/q+bg97h/p9VZCRE2YQyVZhmVpYQTKp2CBb9a+MFbyQkVH\ncWibYCY9s8riTQhUTrXGOtqesumWkTDdacbyuMjobme4WPX8L3xlX5spttpkZQfc\neC0hpwX8bKRUuQifHPAhjuYxcVWIOZk5OaprHxwoXtM0oSNPaGiPCM0fq4GmnF1n\n3Eg5AlEA4aB6F0pG5ajnycvWETz/WZpv/wkcO0UlbgSFlx2OD545CKYcZlbx22bl\nWvYHvkio1AAg03oFQfXNtcl6274s2WFEJw5v0UBk0VHGq2zeTDUCUQDbeqkepngF\njyuRSzfViuA3jpO/8zmFm6Fpr5eCNgqEf+uC7zF+dg9bnnfEA88+x8IjuioRvbx7\nkSMjiIijQUgo103vXadpPhBXFx7EadBDXwJQV0wtEQfXKJLSo/xvJhpQvk2H2cif\nmLsnQUsUmSSBS7+vV45V3K71QyurwCcDVfdtAyHNkaVblWrSneyH0a/iUHVW1jm6\nv97HY0ndsYQc+qUCUQC3Al24wAh+YjZq7bR97FIwIUQUH4TMYsxCKveDzPoSJ/RC\ndp7nmxwNQmMNYDvUVo8MaXQg3PwocQpC29tLfejknTtQJ+CrgePwKsgt8SmGswJQ\nVt10NCsGdK7ACTz1Asfcb4JQUYM/d14ofhJRHptROLE93gHx9He+JGq4ET74YQvd\nD8V0L923eLixsHh5I5t/1QEVwbpeGcDhb+j8LeVvV8w=\n-----END RSA PRIVATE KEY-----\n",
          "ksk_alg": 8,
          "ksk_keytag": 57949,
          "until": "2021-03-02T08:38:09.630312Z",
          "zsk": "-----BEGIN RSA PRIVATE KEY-----\nMIICXQIBAAKBgQDXaUmIPE734cR0Uxtc6wj11rhv4DdP6tnc0LTN7pus1ZdLCBUC\nln3HXKMKYptdyuHrkqs5bQQfl8A47/X21m+sYtJkxdHNDYDkPwrX+bEDgbRgZKKW\n0IMQ7lw0wtYyWlE1Zc4zfZvCmKFWnE24TBQQLcJ+iwtbBGH8IgrAA5N3FQIDAQAB\nAoGBAIozFGgBOTCzedSflQiSChefAIlWMmZlaAzRIY6VLO8/wWbz8nbMkjmbZ0a8\naK1OAo+ec5fOJz0VoM9mtEj+3nlvQoJBw1ubBy4o3yr6X8dOwyEqtH8Riciv9XlE\nDg6uQH8u52CErzYd7io9NVn+vQZEFdw1kwy9bHl6Zb+SwwWpAkEA69Dw7b2VC4aP\na/wr0/xME2hXb7qf2YsH3GreJHTH1D7fdQozKdw4o8tUFjKvOTy827N2X7PSp+cW\nXYzk7Pp7nwJBAOnZPx2KK58IqBdmRpSfdQmstbC9k9SWby1NxH7xerepdRr+Fvnr\nSVZo4JcIyWk1FVUHd9ZNIagIJZhE2tRWkMsCQDPX05/wtfu6sX1ECz6nkPITVmWx\n2cKx1iCXPg81vVjkGaxZebYSPEGGSg43Rl6HA94pLjUMC5vuKfSXLR0MVHECQEWu\n6ADccH02bihy4KtfDNgyL/4Xr9qUbVK5rskJGkFqbKv7dUtJ0pO+Mtau1p3UJKQu\n0oX4fAP/UXybX/4QQZsCQQCcym4PAXhtW5U1FmV/dGCMb8rufZt7bmHHPulrAIVv\n5Zse+HIV/u0c36RRHSRuW4MPICrHE7Uf5B7/7TcWp3nZ\n-----END RSA PRIVATE KEY-----\n",
          "zsk_alg": 8,
          "zsk_keytag": 15271
        },
        {
          "inception": "2020-12-02T10:45:48.279746Z",
          "ksk": "-----BEGIN RSA PRIVATE KEY-----\nMIIC7QIBAAKBoQCz4ZqM5581jG8dIfkXMiPgYtrc5Tp3fwG2Su4l4BmOtpWaOONv\nuk6WTZZHhRKpPmCsVHHu9EVpBvyx7iXssH5j8kkq2tq2Btz957QIG3K28DA2vXJm\nFRJ0tvjmxBXqqMHKHuJI88uduPbJDJ/R5fA+aVl6dBG8zkrikkQxRGhnzcnL3PP1\nX3BIvC8FH305KvGRRPT+kBKsngzOMjtl5qErAgMBAAECgaEAmKofJfkqaSMP5pS/\nuA0I39ZmU9WEgohbJqB/b8u7RSD25RXlCR0At5WPtpFdHiBfocJlk9ziz9lrO4OX\n0kKUcjTeHi3yM0yt4Bv28m6BNHpFvrdo31jOpSkvYzcip2LdYENMTxAi4NSsDDQg\nLjuxbKJskvHgwz73XXj9g6X0uiotTzuUnT0gWJvIDykeXnoru2U2YfYjsN4uSHJF\nPWYlwQJRAOgxqQv1pe7VSQ4sLAnwW3NsGPMHCmAbmcbsjxnPj8Wjf4L0ervHxebt\nnZOCaUlUxZm9X8GiONZAGMG2xPz6tuKYz9wE/6j+9jtFe25alaCLAlEAxlLnapw5\ne3oYElrw1MR1aNOwiSXJuhQ8wlM6EifuV9HA/Aq3AApOoKmwL3n9EqfxuZbFmuRA\nu4FB78tFckIyhqhxHNz9KNZR5ZkwUdWvdeECUBLk/6GWgsM1nfVGSOsiIP76e+lC\n2GhLtq7GTzrFdiiaDmVEqbwgHI2XJmx7fz/VYyMIkwM5xTBCFQGmcs83Q6yazMdV\nrMw+uyDFna60NlrTAlBnPVkCgnjZ8mD9jSG5YNvNygUoH+e3WjmW30RnlynXxXU0\nv08sUjFEKZFx5Yr8XzjSZ85OJ2wbL9pnPeXU6OjseFsJr3CKBad0Yh5pO1evgQJR\nAMFyXCvulXFDKMqV3ePut7pMGGTUl53qoEOYGPsokl+C2Ho7sOgR2wzNLpchYZNr\nS4eCZDPgcC+1JAVOUoDK8IyPbnQaZ0K3kGWxPpzC29xj\n-----END RSA PRIVATE KEY-----\n",
          "ksk_alg": 8,
          "ksk_keytag": 61079,
          "until": "2021-03-02T10:45:48.279414Z",
          "zsk": "-----BEGIN RSA PRIVATE KEY-----\nMIICXQIBAAKBgQDQCr6AbSI9hsy6WsAzZv87brsSG1NpbYnCuZTMIrCzfB2NUF43\nRZPqTgh6dV7EtjnXeq0MsvyCbwRBRXnmQ6MlHqGtovd0k0xEzGWf3V9WLST0J8PD\nCdG7sX3gsWRkVZm6buKfmHmdgBTdWUs4ig+x7p7pwVhV0HO7x0StEEgUxwIDAQAB\nAoGANs891TPrW25SLZ6PGHvALnZDzsdoOFRlgOnHq+hPyVmfp4VO7RzllUstrKWT\nbBveLUjion/dSrfY1SFqtiGHr1w7tzTW39kTEdca4lvUtSmt7//wrEV0GLsgHwnZ\nVVyCuH0PpRcSmYYVYrSsCEH9/mXxs8Fq0tsn+wMls7O1WWECQQDruuKG/X/tYmps\nm239lLH8VyDRqQmX3mdtz+uKI8J37a+emd7lOWmkqa6b2ep+sZPDEk8xR7ktSiDb\nAhyf85jvAkEA4e5dBtUG05ieO+XtzvZOdMiU4zdWSAtgIyqegXunnvulwddEFbw0\njwRzW5MYo0eTRfgaS0obMw8uZ0hN7zPRqQJBAOH1+ZCWTNta/FLxRqTNtTMCvcXb\nuANowFIl/U0kbBQTtcVdD6lAuICL2oEwiTQ6uj5CPcEqVFoSdZ4ZzyCQG+cCQDBv\ni54FWXtPgszQlFUEVPmQburvWB4F4kxnvKeBvQPGa1jNL5mBSbtHdvuw411N4PLl\nJ63wazhdDtOxmpOnhlECQQCfdp/ZOAKUalTUuqZLgIGwobDAmcOzXN/85WWlWLIx\nDf1j0nabGCBLJt6VB0oVHd9a7rC7oTcl3TjO3kP9Zhts\n-----END RSA PRIVATE KEY-----\n",
          "zsk_alg": 8,
          "zsk_keytag": 49225
        }
      ],
      "sha": "10ea56ad7be9d3e6e75be3a15ef0dfabe9facafba486d74914e7baf8fb36638e"
    }
    """,
    iolist_to_binary(I).
