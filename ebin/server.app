{application,erldns,
             [{description,"Erlang Authoritative DNS Server"},
              {vsn,"34"},
              {modules,[fake_responder,mysql_responder,records,rr,server,
                        unpack]},
              {registered,[]},
              {mod,{erldns,[]}},
              {applications,[kernel,stdlib,mysql]}]}.
