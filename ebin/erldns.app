{application,erldns,
             [{description,"Erlang Authoritative DNS Server"},
              {vsn,"63d849e"},
              {modules,[erldns,erldns_app,erldns_fake_responder,
                        erldns_mysql_responder,erldns_packet_cache,
                        erldns_records,erldns_server,erldns_sup]},
              {registered,[erldns_server]},
              {mod,{erldns_app,[]}},
              {applications,[kernel,stdlib]}]}.
