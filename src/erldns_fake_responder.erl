-module(erldns_fake_responder).
-include("include/nsrecs.hrl").
-export([answer/1]).

answer(Questions) ->
  lists:flatten(lists:map(
      fun(Q) ->
          Qname = Q#question.qname,
          case erldns_records:type_to_atom(Q#question.qtype) of
            soa     -> fake_soa_record(Qname);
            a       -> fake_a_records(Qname);
            aaaa    -> fake_aaaa_records(Qname); % broken
            cname   -> fake_cname_records(Qname);
            ns      -> fake_ns_records(Qname);
            mx      -> fake_mx_records(Qname);
            txt     -> fake_txt_records(Qname);
            srv     -> fake_srv_records(Qname);
            naptr   -> fake_naptr_records(Qname);
            ptr     -> fake_ptr_records(Qname);
            spf     -> fake_spf_records(Qname);
            sshfp   -> fake_sshfp_records(Qname);
            rp      -> fake_rp_records(Qname);
            hinfo   -> fake_hinfo_records(Qname);
            afsdb   -> fake_afsdb_records(Qname);

            any     -> lists:flatten([fake_soa_record(Qname), fake_a_records(Qname), fake_mx_records(Qname)]);

            % DNSSEC RRs
            dnskey  -> fake_dnskey_records(Qname);
            ds      -> fake_ds_records(Qname); % broken
            rrsig   -> fake_rrsig_records(Qname);
            %nsec    -> fake_nsec_records(Qname);

            _       -> []
          end
      end,
      Questions)).

fake_soa_record(Qname) ->
  [#rr {
      rname = Qname,
      type = 6,
      class = 1,
      ttl = 3600,
      rdata = "ns1.example.com root.example.com 2011072801 10800 3600 86400 300"
    }
  ].

fake_a_records(Qname) ->
  [#rr {
      rname = Qname,
      type = 1,
      class = 1,
      ttl = 3600,
      rdata = "1.2.3.4"
    }
  ].

fake_aaaa_records(Qname) ->
  [#rr {
      rname = Qname,
      type = 28,
      class = 1,
      ttl = 3600,
      rdata = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    }
  ].

fake_cname_records(Qname) ->
  [#rr {
      rname = Qname,
      type = 5,
      class = 1,
      ttl = 3600,
      rdata = "example.com"
    }
  ].

fake_mx_records(Qname) ->
  [#rr {
      rname = Qname,
      type = 15,
      class = 1,
      ttl = 3600,
      rdata = "1 mx1.example.com"
    },
    #rr {
      rname = Qname,
      type = 15,
      class = 1,
      ttl = 3600,
      rdata = "2 mx2.example.com"
    }
  ].

fake_ns_records(Qname) ->
  [#rr {
      rname = Qname,
      type = 2,
      class = 1,
      ttl = 3600,
      rdata = "ns1.example.com"
    },
    #rr {
      rname = Qname,
      type = 2,
      class = 1,
      ttl = 3600,
      rdata = "ns2.example.com"
    }
  ].

fake_txt_records(Qname) ->
  [
    #rr {
      rname = Qname,
      type = 16,
      class = 1,
      ttl = 3600,
      rdata = "Just another text record"
    },
    #rr {
      rname = Qname,
      type = 16,
      class = 1,
      ttl = 3600,
      rdata = "\"Multiple text strings\" \"in a single resource record\""
    }
  ].

fake_srv_records(Qname) ->
  [
    #rr {
      rname = string:concat("_foo._tcp", Qname),
      type = 33,
      class = 1,
      ttl = 3600,
      rdata = "1 0 9 server.example.com"
    }
  ].

fake_naptr_records(Qname) ->
  [
    #rr {
      rname = Qname,
      type = 35,
      class = 1,
      ttl = 3600,
      rdata = "100 100 \"s\" \"http+I2R\" \"\" _http._tcp.foo.com"
    }
  ].

fake_ptr_records(Qname) ->
  [
    #rr {
      rname = Qname,
      type = 12,
      class = 1,
      ttl = 3600,
      rdata = "foo.example.com"
    }
  ].

fake_spf_records(Qname) ->
  [
    #rr {
      rname = Qname,
      type = 99,
      class = 1,
      ttl = 3600,
      rdata = "v=spf1 +mx a:colo.example.com/28 -all"
    }
  ].

fake_sshfp_records(Qname) ->
  [
    #rr {
      rname = Qname,
      type = 44,
      class = 1,
      ttl = 3600,
      rdata = "2 1 123456789abcdef67890123456789abcdef67890"
    }
  ].

fake_rp_records(Qname) ->
  [
    #rr {
      rname = Qname,
      type = 17,
      class = 1,
      ttl = 3600,
      rdata = "joe.example.com joe-txt.example.com"
    }
  ].

fake_hinfo_records(Qname) ->
  [
    #rr {
      rname = Qname,
      type = 13,
      class = 1,
      ttl = 3600,
      rdata = "i386 linux"
    }
  ].

fake_afsdb_records(Qname) ->
  [
    #rr {
      rname = Qname,
      type = 18,
      class = 1,
      ttl = 3600,
      rdata = "1 bigbird.example.com"
    }
  ].

fake_dnskey_records(Qname) ->
  [
    #rr {
      rname = Qname,
      type = 48,
      class = 1,
      ttl = 3600,
      rdata = "256 3 5 AQPSKmynfzW4kyBv015MUG2DeIQ3Cbl+BBZH4b/0PY1kxkmvHjcZc8nokfzj31GajIQKY+5CptLr3buXA10hWqTkF7H6RfoRqXQeogmMHfpftf6zMv1LyBUgia7za6ZEzOJBOztyvhjL742iU/TpPSEDhm2SNKLijfUppn1UaNvv4w=="
    }
  ].

fake_ds_records(Qname) ->
  [
    #rr {
      rname = Qname,
      type = 43,
      class = 1,
      ttl = 3600,
      rdata = "60485 5 1 2BB183AF5F22588179A53B0A98631FAD1A292118"
    }
  ].

fake_rrsig_records(Qname) ->
  [
    #rr {
      rname = Qname,
      type = 46,
      class = 1,
      ttl = 3600,
      rdata = "A 5 3 3600 20030322173103 20030220173103 2642 example.com oJB1W6WNGv+ldvQ3WDG0MQkg5IEhjRip8WTrPYGv07h108dUKGMeDPKijVCHX3DDKdfb+v6oB9wfuh3DTJXUAfI/M0zmO/zz8bW0Rznl8O3tGNazPwQKkRN20XPXV6nwwfoXmJQbsLNrLfkGJ5D6fwFm8nN+6pBzeDQfsS3Ap3o="
    }
  ].                              
