%% @doc Handler for the ALIAS record type. The ALIAS record takes a fully-qualified host
%% name and resolves it to one or more A or AAAA records at request time.
%%
%% The ALIAS record can be used in place of an A record, AAAA record and/or CNAME record.

-module(erldns_zone_cache_test).

-include_lib("dns_erlang/include/dns.hrl").
-include_lib("erldns/include/erldns.hrl").
-include_lib("eunit/include/eunit.hrl").

-define(TEST_MODULE, erldns_zone_cache).

setup_cache() ->
    logger:set_application_level(erldns, debug),
    meck:new(folsom_metrics),
    meck:expect(
        folsom_metrics,
        histogram_timed_update,
        fun(_, Module, Handler, Args) -> erlang:apply(Module, Handler, Args) end
    ),
    {ok, Pid} = erldns_zone_parser:start_link(),
    erldns_storage:create(schema),
    erldns_storage:create(zones),
    erldns_storage:create(zone_records_typed),
    erldns_storage:create(authorities),
    Pid.

load_dnssec_zone() ->
    erldns_storage:load_zones("test/dnssec-zone.json").

load_standard_zone() ->
    erldns_storage:load_zones("test/standard-zone.json").

teardown_cache(Pid) ->
    ?assert(meck:validate(folsom_metrics)),
    gen_server:stop(Pid),
    ets:delete_all_objects(sync_counters),
    meck:unload(folsom_metrics).

put_zone_rrset_records_count_with_existing_rrset_test() ->
    Pid = setup_cache(),
    load_standard_zone(),
    ZoneName = <<"example.com">>,
    ZoneBase = erldns_zone_cache:find_zone(erldns:normalize_name(ZoneName)),
    erldns_zone_cache:put_zone_rrset(
        {ZoneName, <<"irrelevantDigest">>,
            [
                #dns_rr{
                    data = #dns_rrdata_cname{dname = <<"google.com">>},
                    name = <<"cname.example.com">>,
                    ttl = 5,
                    type = 5
                }
            ],
            []},
        <<"cname.example.com">>,
        5,
        1
    ),
    ZoneModified = erldns_zone_cache:find_zone(erldns:normalize_name(ZoneName)),
    % There should be no change in record count
    ?assertEqual(ZoneBase#zone.record_count, ZoneModified#zone.record_count),
    teardown_cache(Pid).

put_zone_rrset_records_count_with_new_rrset_test() ->
    Pid = setup_cache(),
    load_standard_zone(),
    ZoneName = <<"example.com">>,
    ZoneBase = erldns_zone_cache:find_zone(erldns:normalize_name(ZoneName)),
    erldns_zone_cache:put_zone_rrset(
        {ZoneName, <<"irrelevantDigest">>,
            [
                #dns_rr{
                    data = #dns_rrdata_a{ip = <<"5,5,5,5">>},
                    name = <<"a2.example.com">>,
                    ttl = 5,
                    type = 1
                }
            ],
            []},
        <<"a2.example.com">>,
        5,
        1
    ),
    ZoneModified = erldns_zone_cache:find_zone(erldns:normalize_name(ZoneName)),
    % New RRSet is being added with one record we should see an increase by 1
    ?assertEqual(ZoneBase#zone.record_count + 1, ZoneModified#zone.record_count),
    teardown_cache(Pid).

put_zone_rrset_records_count_matches_cache_test() ->
    Pid = setup_cache(),
    load_standard_zone(),
    ZoneName = <<"example.com">>,
    erldns_zone_cache:put_zone_rrset(
        {ZoneName, <<"irrelevantDigest">>,
            [
                #dns_rr{
                    data = #dns_rrdata_a{ip = <<"5,5,5,5">>},
                    name = <<"a2.example.com">>,
                    ttl = 5,
                    type = 1
                }
            ],
            []},
        <<"a2.example.com">>,
        5,
        1
    ),
    ZoneModified = erldns_zone_cache:find_zone(erldns:normalize_name(ZoneName)),
    % New RRSet is being added with one record we should see an increase by 1
    ?assertEqual(length(erldns_zone_cache:get_zone_records(ZoneName)), ZoneModified#zone.record_count),
    teardown_cache(Pid).

put_zone_rrset_records_count_with_dnssec_zone_and_new_rrset_test() ->
    Pid = setup_cache(),
    load_dnssec_zone(),
    ZoneName = <<"example-dnssec.com">>,
    Zone = erldns_zone_cache:find_zone(erldns:normalize_name(ZoneName)),
    erldns_zone_cache:put_zone_rrset(
        {ZoneName, <<"irrelevantDigest">>,
            [
                #dns_rr{
                    data = #dns_rrdata_cname{dname = <<"google.com">>},
                    name = <<"cname.example-dnssec.com">>,
                    ttl = 60,
                    type = 5
                }
            ],
            []},
        <<"cname.example-dnssec.com">>,
        5,
        1
    ),
    ZoneModified = erldns_zone_cache:find_zone(erldns:normalize_name(ZoneName)),
    % New RRSet entry for the CNAME + 1 RRSig record
    ?assertEqual(Zone#zone.record_count + 2, ZoneModified#zone.record_count),
    teardown_cache(Pid).

delete_zone_rrset_records_count_width_existing_rrset_test() ->
    Pid = setup_cache(),
    load_standard_zone(),
    ZoneName = <<"example.com">>,
    ZoneBase = erldns_zone_cache:find_zone(erldns:normalize_name(ZoneName)),
    erldns_zone_cache:delete_zone_rrset(
        ZoneName,
        <<"irrelevantDigest">>,
        erldns:normalize_name(<<"cname.example.com">>),
        5,
        1
    ),
    ZoneModified = erldns_zone_cache:find_zone(erldns:normalize_name(ZoneName)),
    % Deletes a CNAME RRSet with one record
    ?assertEqual(ZoneBase#zone.record_count - 1, ZoneModified#zone.record_count),
    teardown_cache(Pid).

delete_zone_rrset_records_count_width_dnssec_zone_and_existing_rrset_test() ->
    Pid = setup_cache(),
    load_dnssec_zone(),
    ZoneName = <<"example-dnssec.com">>,
    ZoneBase = erldns_zone_cache:find_zone(erldns:normalize_name(ZoneName)),
    erldns_zone_cache:delete_zone_rrset(
        ZoneName,
        <<"irrelevantDigest">>,
        erldns:normalize_name(<<"cname2.example-dnssec.com">>),
        5,
        2
    ),
    ZoneModified = erldns_zone_cache:find_zone(erldns:normalize_name(ZoneName)),
    % Deletes a CNAME RRSet with one record + RRSig
    ?assertEqual(ZoneBase#zone.record_count - 2, ZoneModified#zone.record_count),
    teardown_cache(Pid).

delete_zone_rrset_records_count_matches_cache_test() ->
    Pid = setup_cache(),
    load_dnssec_zone(),
    ZoneName = <<"example-dnssec.com">>,
    erldns_zone_cache:delete_zone_rrset(
        ZoneName,
        <<"irrelevantDigest">>,
        erldns:normalize_name(<<"cname2.example-dnssec.com">>),
        5,
        2
    ),
    ZoneModified = erldns_zone_cache:find_zone(erldns:normalize_name(ZoneName)),
    % Deletes a CNAME RRSet with one record + RRSig
    ?assertEqual(length(erldns_zone_cache:get_zone_records(ZoneName)), ZoneModified#zone.record_count),
    teardown_cache(Pid).
