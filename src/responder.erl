-module(responder).
-include("include/nsrecs.hrl").
-export([answer/1]).

answer(Questions) ->
  lists:flatten(lists:map(
      fun(Q) ->
          Qname = Q#question.qname,
          case records:type_to_atom(Q#question.qtype) of
            soa     -> fake_soa_record(Qname);
            a       -> fake_a_records(Qname);
            cname   -> fake_cname_records(Qname);
            ns      -> fake_ns_records(Qname);
            mx      -> fake_mx_records(Qname);
            txt     -> fake_txt_records(Qname);
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
    }
  ].
