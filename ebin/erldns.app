{application,erldns,
             [{description,"Erlang Authoritative DNS Server"},
              {vsn,"0.0.1"},
              {modules,[erldns,erldns_fake_responder,erldns_mysql_responder,
                        erldns_pack,erldns_records,erldns_server,
                        erldns_unpack]},
              {registered,[]},
              {mod,{erldns,[]}},
              {applications,[kernel,stdlib,mysql]}]}.
