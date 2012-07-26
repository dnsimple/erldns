-module(responder).
-include("include/nsrecs.hrl").
-export([answer/1]).

answer(Questions) ->
  lists:flatten(lists:map(
      fun(Q) ->
          case records:type_to_atom(Q#question.qtype) of
            a ->
              [#rr {
                  rname = Q#question.qname,
                  type = 1,
                  class = 1,
                  ttl = 3600,
                  rdata = "1.2.3.4"
                }
              ];

            cname ->
              [#rr {
                  rname = Q#question.qname,
                  type = 5,
                  class = 1,
                  ttl = 3600,
                  rdata = "example.com"
                .
              ];

            ns ->
              [#rr {
                  rname = Q#question.qname,
                  type = 2,
                  class = 1,
                  ttl = 3600,
                  rdata = "ns1.example.com"
                },
                #rr {
                  rname = Q#question.qname,
                  type = 2,
                  class = 1,
                  ttl = 3600,
                  rdata = "ns2.example.com"
                }
              ];

            _ -> []
          end
      end,
      Questions)).


