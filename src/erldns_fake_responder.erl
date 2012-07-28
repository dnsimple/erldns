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
