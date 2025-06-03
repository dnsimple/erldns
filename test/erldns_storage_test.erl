-module(erldns_storage_test).

-include_lib("eunit/include/eunit.hrl").

load_zones_with_existing_file_test() ->
    {ok, Pid} = erldns_zone_parser:start_link(),
    erldns_zone_cache:create(zones),
    erldns_zone_cache:create(zone_records_typed),
    Filename = filename:join(tmp_dir(), "zones.json"),

    ok = file:write_file(
        Filename,
        <<"[{\"name\": \"example.com\", \"records\": [{\"name\": \"example.com\", \"type\": \"SOA\", \"data\": {\"mname\": \"ns1.example.com\", \"rname\": \"ahu.example.com\", \"serial\": 2000081501, \"refresh\": 28800, \"retry\": 7200, \"expire\": 604800, \"minimum\": 86400}, \"ttl\": 100000}]}]">>
    ),

    ?assertMatch({ok, 1}, erldns_zone_loader:load_zones(#{path => Filename, strict => true})),
    gen_server:stop(Pid).

%% Helpers

tmp_dir() ->
    maybe
        false ?= os:getenv("TMPDIR"),
        false ?= os:getenv("TEMP"),
        false ?= os:getenv("TMP"),
        "/tmp"
    else
        Dir -> Dir
    end.
