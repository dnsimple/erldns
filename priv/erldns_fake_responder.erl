-module(erldns_fake_responder).
-include("dns.hrl").
-export([answer/2]).

answer(Qname, Qtype) ->
  case Qtype of
    <<"SOA">>     -> fake_soa_record(Qname);
    <<"A">>       -> fake_a_records(Qname);
    <<"AAAA">>    -> fake_aaaa_records(Qname);
    <<"CNAME">>   -> fake_cname_records(Qname);
    <<"NS">>      -> fake_ns_records(Qname);
    <<"MX">>      -> fake_mx_records(Qname);
    <<"TXT">>     -> fake_txt_records(Qname);
    <<"SRV">>     -> fake_srv_records(Qname);
    <<"NAPTR">>   -> fake_naptr_records(Qname);
    <<"PTR">>     -> fake_ptr_records(Qname);
    <<"SPF">>     -> fake_spf_records(Qname);
    <<"SSHFP">>   -> fake_sshfp_records(Qname);
    <<"RP">>      -> fake_rp_records(Qname);
    <<"HINFO">>   -> fake_hinfo_records(Qname);
    <<"AFSDB">>   -> fake_afsdb_records(Qname);

    <<"ANY">>     -> fake_records(Qname);

    %% DNSSEC RRs
    <<"DNSKEY">>  -> fake_dnskey_records(Qname);
    <<"DS">>      -> fake_ds_records(Qname); % Broken (certainly my fault)
    <<"RRSIG">>   -> fake_rrsig_records(Qname);
    %<<"RRSIG">>   -> fake_generated_rrsig_records(fake_a_records(Qname), Qname, KeyTag, Alg, Key)
    <<"NSEC">>    -> fake_generated_nsec_records(fake_records(Qname));

    %% Nothing found
    _ -> []
  end.

fake_records(Qname) ->
  lists:flatten([fake_soa_record(Qname), fake_a_records(Qname), fake_mx_records(Qname)]).

fake_soa_record(Qname) ->
  [#dns_rr {
      name = Qname,
      type = 6,
      ttl = 3600,
      data = #dns_rrdata_soa{mname = "ns1.example.com", rname = "root.example.com", serial = 2011072801, refresh = 10800, retry = 3600, expire = 86400, minimum = 300}
      %data = "ns1.example.com root.example.com 2011072801 10800 3600 86400 300"
    }
  ].

fake_a_records(Qname) ->
  [#dns_rr {
      name = Qname,
      type = 1,
      ttl = 3600,
      data = #dns_rrdata_a{ip = {1,2,3,4}}
    }
  ].

fake_aaaa_records(Qname) ->
  [#dns_rr {
      name = Qname,
      type = 28,
      ttl = 3600,
      data = #dns_rrdata_aaaa{ip = {1,2,3,4,5,6,7,8}}
      %data = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    }
  ].

fake_cname_records(Qname) ->
  [#dns_rr {
      name = Qname,
      type = 5,
      ttl = 3600,
      data = #dns_rrdata_cname{dname = "dest.example.com"}
    }
  ].

fake_ns_records(Qname) ->
  [#dns_rr {
      name = Qname,
      type = 2,
      ttl = 3600,
      data = #dns_rrdata_ns{dname = "ns1.example.com"}
    },
    #dns_rr {
      name = Qname,
      type = 2,
      ttl = 3600,
      data = #dns_rrdata_ns{dname = "ns2.example.com"}
    }
  ].

fake_mx_records(Qname) ->
  [#dns_rr {
      name = Qname,
      type = 15,
      ttl = 3600,
      data = #dns_rrdata_mx{exchange = "mx1.example.com", preference = 1}
    },
    #dns_rr {
      name = Qname,
      type = 15,
      ttl = 3600,
      data = #dns_rrdata_mx{exchange = "mx2.example.com", preference = 2}
    }
  ].

fake_txt_records(Qname) ->
  [
    #dns_rr {
      name = Qname,
      type = 16,
      ttl = 3600,
      data = #dns_rrdata_txt{txt = "Just another text record"}
    },
    #dns_rr {
      name = Qname,
      type = 16,
      ttl = 3600,
      data = #dns_rrdata_txt{txt = ["Multiple text strings", "in a single resource record"]}
    }
  ].

fake_srv_records(Qname) ->
  Prefix = <<"_foo._tcp.">>,
  [
    #dns_rr {
      name = <<Prefix/bitstring, Qname/bitstring>>,
      type = 33,
      ttl = 3600,
      data = #dns_rrdata_srv{priority = 1, weight = 0, port = 9, target = "server.example.com"}
    }
  ].

fake_naptr_records(Qname) ->
  [
    #dns_rr {
      name = Qname,
      type = 35,
      ttl = 3600,
      data = #dns_rrdata_naptr{order = 100, preference = 100, flags = <<"s">>, services = <<"http+I2R">>, regexp = <<"">>, replacement = <<"_http._tcp.foo.com">>}
    }
  ].

fake_ptr_records(Qname) ->
  [
    #dns_rr {
      name = Qname,
      type = 12,
      ttl = 3600,
      data = #dns_rrdata_ptr{dname = "foo.example.com"}
    }
  ].

fake_spf_records(Qname) ->
  [
    #dns_rr {
      name = Qname,
      type = 99,
      ttl = 3600,
      data = #dns_rrdata_spf{spf = "v=spf1 +mx a:colo.example.com/28 -all"}
    }
  ].

fake_sshfp_records(Qname) ->
  [
    #dns_rr {
      name = Qname,
      type = 44,
      ttl = 3600,
      data = #dns_rrdata_sshfp{alg = 2, fp_type = 1, fp = <<"123456789abcdef67890123456789abcdef67890">>}
    }
  ].

fake_rp_records(Qname) ->
  [
    #dns_rr {
      name = Qname,
      type = 17,
      ttl = 3600,
      data = #dns_rrdata_rp{mbox = "joe.example.com", txt = "joe-txt.example.com"}
    }
  ].

fake_hinfo_records(Qname) ->
  [
    #dns_rr {
      name = Qname,
      type = 13,
      ttl = 3600,
      data = #dns_rrdata_hinfo{cpu = "i386", os = "linux"}
    }
  ].

fake_afsdb_records(Qname) ->
  [
    #dns_rr {
      name = Qname,
      type = 18,
      ttl = 3600,
      data = #dns_rrdata_afsdb{subtype = 1, hostname = "bigbird.example.com"}
    }
  ].

fake_dnskey_records(Qname) ->
  [
    dnssec:add_keytag_to_dnskey(#dns_rr {
      name = Qname,
      type = 48,
      ttl = 3600,
      data = #dns_rrdata_dnskey{flags = 256, protocol = 3, alg = 5, public_key = <<"AQPSKmynfzW4kyBv015MUG2DeIQ3Cbl+BBZH4b/0PY1kxkmvHjcZc8nokfzj31GajIQKY+5CptLr3buXA10hWqTkF7H6RfoRqXQeogmMHfpftf6zMv1LyBUgia7za6ZEzOJBOztyvhjL742iU/TpPSEDhm2SNKLijfUppn1UaNvv4w==">>}
    })
  ].

fake_ds_records(Qname) ->
  [
    #dns_rr {
      name = Qname,
      type = 43,
      ttl = 3600,
      data = #dns_rrdata_ds{keytag = 8401, alg = 5, digest_type = 1, digest = <<"5248DB0EAE4E829924F19D33B005FBC8C4606058">>}
    }
  ].

fake_rrsig_records(Qname) ->
  [
    #dns_rr {
      name = Qname,
      type = 46,
      ttl = 3600,
      data = #dns_rrdata_rrsig{type_covered = 1, alg = 5, labels = 3, original_ttl = 3600, expiration = 20030322173103, inception = 20030220173103, key_tag = 2642, signers_name = "example.com", signature = <<"oJB1W6WNGv+ldvQ3WDG0MQkg5IEhjRip8WTrPYGv07h108dUKGMeDPKijVCHX3DDKdfb+v6oB9wfuh3DTJXUAfI/M0zmO/zz8bW0Rznl8O3tGNazPwQKkRN20XPXV6nwwfoXmJQbsLNrLfkGJ5D6fwFm8nN+6pBzeDQfsS3Ap3o=">>}
    }
  ].

%fake_generated_rrsig_records(RSet, SignerName, KeyTag, Alg, Key) ->
  %dnssec:sign_rrset(RSet, SignerName, KeyTag, Alg, Key).

%fake_nsec_records(Qname) ->
  %[
    %#dns_rr {
      %name = Qname,
      %type = ?DNS_TYPE_NSEC_NUMBER,
      %ttl = 3600,
      %data = #dns_rrdata_nsec{next_dname = "example.com", types = [?DNS_TYPE_A_NUMBER]}
    %}
  %].

fake_generated_nsec_records(RSet) ->
  dnssec:gen_nsec(RSet).
