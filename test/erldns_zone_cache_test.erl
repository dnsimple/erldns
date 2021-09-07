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
    lager:start(),
    lager:set_loglevel(lager_console_backend, debug),
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

% load_dnssec_zone() ->
%     erldns_storage:load_zones("test/dnssec-zone.json").

load_standard_zone() ->
    erldns_storage:load_zones("test/standard-zone.json").

teardown_cache(Pid) ->
    ?assert(meck:validate(folsom_metrics)),
    gen_server:stop(Pid),
    meck:unload(folsom_metrics).

put_zone_rrset_records_count_test() ->
    Pid = setup_cache(),
    load_standard_zone(),
    ZoneName = <<"example.com">>,
    ZoneBase = erldns_zone_cache:find_zone(erldns:normalize_name(ZoneName)),
    erldns_zone_cache:put_zone_rrset({ZoneName,
                                    <<"82a24ff949c33f4c6091990ff6b6e5b697d7093c4b5c37827b90b9b75cd9151d">>,
                                    [#dns_rr{data = #dns_rrdata_cname{dname = <<"google.com">>},
                                            name  = <<"cname.example.com">>, ttl = 5, type = 5}], []},
                                            <<"cname.example.com">>, 5, 1),
    ZoneModified = erldns_zone_cache:find_zone(erldns:normalize_name(ZoneName)),
    % Existing CNAME RRset with one 1 entry in the fixtures
    ?assertEqual(ZoneBase#zone.record_count, ZoneModified#zone.record_count),
    teardown_cache(Pid).

delete_zone_rrset_records_count_test() ->
    Pid = setup_cache(),
    load_standard_zone(),
    ZoneName = <<"example.com">>,
    ZoneBase = erldns_zone_cache:find_zone(erldns:normalize_name(ZoneName)),
    erldns_zone_cache:delete_zone_rrset(ZoneName,
                                    <<"82a24ff949c33f4c6091990ff6b6e5b697d7093c4b5c37827b90b9b75cd9151d">>,
                                    erldns:normalize_name(<<"cname.example.com">>), 5, 0),
    ZoneModified = erldns_zone_cache:find_zone(erldns:normalize_name(ZoneName)),
    % one RRSet record in the fixtures
    ?assertEqual(ZoneBase#zone.record_count, ZoneModified#zone.record_count),
    teardown_cache(Pid).
