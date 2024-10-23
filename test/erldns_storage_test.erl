-module(erldns_storage_test).

-feature(maybe_expr, enable).

-include_lib("dns_erlang/include/dns.hrl").
-include_lib("erldns/include/erldns.hrl").
-include_lib("eunit/include/eunit.hrl").

-define(TEST_MODULE, erldns_storage).

load_zones_with_existing_file_test() ->
    {ok, Pid} = erldns_zone_parser:start_link(),
    erldns_storage:create(zones),
    erldns_storage:create(zone_records_typed),
    Filename = filename:join(tmp_dir(), "zones.json"),

    ok = file:write_file(
        Filename,
        <<"[{\"name\": \"example.com\", \"records\": [{\"name\": \"example.com\", \"type\": \"SOA\", \"data\": {\"mname\": \"ns1.example.com\", \"rname\": \"ahu.example.com\", \"serial\": 2000081501, \"refresh\": 28800, \"retry\": 7200, \"expire\": 604800, \"minimum\": 86400}, \"ttl\": 100000}]}]">>
    ),

    ?assertMatch({ok, 1}, ?TEST_MODULE:load_zones(Filename)),
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
