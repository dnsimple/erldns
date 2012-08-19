{application,erldns,
             [{description,"Erlang Authoritative DNS Server"},
              {vsn,"c62c6fd"},
              {modules,[erldns,erldns_app,erldns_fake_responder,
                        erldns_mysql_responder,erldns_records,erldns_server,
                        erldns_sup]},
              {registered,[erldns_server]},
              {mod,{erldns_app,[]}},
              {applications,[kernel,stdlib]}]}.
