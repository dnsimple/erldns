{application,erldns,
             [{description,"Erlang Authoritative DNS Server"},
              {vsn,"0.0.1"},
              {modules,[erldns,erldns_fake_responder,erldns_mysql_responder,
                        erldns_records,erldns_server]},
              {registered,[]},
              {mod,{erldns,[]}},
              {applications,[kernel,stdlib,mysql]}]}.
