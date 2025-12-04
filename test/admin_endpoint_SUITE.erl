-module(admin_endpoint_SUITE).
-compile([export_all, nowarn_export_all]).

-behaviour(ct_suite).

-include_lib("stdlib/include/assert.hrl").

-spec all() -> [ct_suite:ct_test_def()].
all() ->
    [{group, all}].

-spec groups() -> [ct_suite:ct_group_def()].
groups() ->
    [
        {all, [parallel], [
            bad_auth,
            delete_queues,
            get_zones,
            get_not_found_resource,
            get_zone_resources,
            get_zone_resources_with_metaonly,
            fake_action_zone,
            get_zone_record_resource,
            get_zone_record_resource_name,
            get_zone_record_resource_name_type,
            get_zone_record_resource_name_type_non_existing,
            get_zone_resources_for_dnssec_signed
        ]}
    ].

-spec init_per_suite(ct_suite:ct_config()) -> ct_suite:ct_config().
init_per_suite(Config0) ->
    AdminPort = 8083,
    FileName = filename:join([code:priv_dir(erldns), "zones/example.com.json"]),
    AppConfig = [
        {erldns, [
            {listeners, [#{name => inet_1, port => 8053}]},
            {zones, #{path => FileName}},
            {admin, [
                {credentials, {<<"username">>, <<"password">>}},
                {port, AdminPort}
            ]}
        ]}
    ],
    Config = app_helper:start_erldns(Config0, AppConfig),
    [{port, AdminPort} | Config].

-spec end_per_suite(ct_suite:ct_config()) -> term().
end_per_suite(Config) ->
    app_helper:stop(Config).

-spec init_per_group(ct_suite:ct_groupname(), ct_suite:ct_config()) -> ct_suite:ct_config().
init_per_group(_, Config) ->
    Config.

-spec end_per_group(ct_suite:ct_groupname(), ct_suite:ct_config()) -> term().
end_per_group(_, _Config) ->
    ok.

-spec init_per_testcase(ct_suite:ct_testcase(), ct_suite:ct_config()) -> ct_suite:ct_config().
init_per_testcase(_, Config) ->
    Config.

-spec end_per_testcase(ct_suite:ct_testcase(), ct_suite:ct_config()) -> term().
end_per_testcase(_, Config) ->
    Config.

%% Tests
bad_auth(CtConfig) ->
    Request = {endpoint(CtConfig, ""), headers(bad_auth)},
    case httpc:request(get, Request, [], []) of
        {_, {{_Version, 401, "Unauthorized"}, _Headers, _Body}} ->
            ok;
        {_, Other} ->
            ct:fail(Other)
    end.

get_zones(CtConfig) ->
    Request = {endpoint(CtConfig, ""), headers(good)},
    case httpc:request(get, Request, [], []) of
        {ok, {{_Version, 200, _ReasonPhrase}, _Headers, Payload}} ->
            Body = json:decode(iolist_to_binary(Payload)),
            ?assertMatch(
                #{
                    <<"erldns">> :=
                        #{
                            <<"zones">> :=
                                #{<<"count">> := N, <<"versions">> := _}
                        }
                } when is_integer(N) andalso N >= 3,
                Body
            );
        {_, Other} ->
            ct:fail(Other)
    end.

delete_queues(CtConfig) ->
    Request = {endpoint(CtConfig, ""), headers(good)},
    case httpc:request(delete, Request, [], []) of
        {ok, {{_Version, 204, "No Content"}, _Headers, _Payload}} ->
            ok;
        {_, Other} ->
            ct:fail(Other)
    end.

get_not_found_resource(CtConfig) ->
    Request = {endpoint(CtConfig, "/zones/non_existing_zone.bad"), headers(good)},
    case httpc:request(get, Request, [], []) of
        {ok, {{_Version, 404, "Not Found"}, _Headers, _Payload}} ->
            ok;
        {_, Other} ->
            ct:fail(Other)
    end.

get_zone_resources(CtConfig) ->
    Request = {endpoint(CtConfig, "/zones/example.com"), headers(good)},
    case httpc:request(get, Request, [], []) of
        {ok, {{_Version, 200, _ReasonPhrase}, _Headers, Payload}} ->
            Body = json:decode(iolist_to_binary(Payload)),
            ?assertMatch(
                #{
                    <<"erldns">> :=
                        #{
                            <<"zone">> :=
                                #{
                                    <<"name">> := <<"example.com">>,
                                    <<"records">> := _,
                                    <<"records_count">> := 11,
                                    <<"version">> := <<>>
                                }
                        }
                },
                Body
            );
        {_, Other} ->
            ct:fail(Other)
    end.

get_zone_resources_with_metaonly(CtConfig) ->
    Request = {endpoint(CtConfig, "/zones/example.com?metaonly=true"), headers(good)},
    case httpc:request(get, Request, [], []) of
        {ok, {{_Version, 200, _ReasonPhrase}, _Headers, Payload}} ->
            Body = json:decode(iolist_to_binary(Payload)),
            ?assertMatch(
                #{
                    <<"erldns">> :=
                        #{
                            <<"zone">> :=
                                #{
                                    <<"name">> := <<"example.com">>,
                                    <<"records_count">> := 11,
                                    <<"version">> := <<>>
                                }
                        }
                },
                Body
            );
        {_, Other} ->
            ct:fail(Other)
    end.

fake_action_zone(CtConfig) ->
    Request = {endpoint(CtConfig, "/zones/example.com/get"), headers(good)},
    case httpc:request(get, Request, [], []) of
        {ok, {{_Version, 200, _ReasonPhrase}, _Headers, ""}} ->
            ok;
        {_, Other} ->
            ct:fail(Other)
    end.

% {"/zones/:zone_name/records[/:record_name]", erldns_admin_zone_records_resource_handler, State}
get_zone_record_resource(CtConfig) ->
    Request = {endpoint(CtConfig, "/zones/example.com/records"), headers(good)},
    case httpc:request(get, Request, [], []) of
        {ok, {{_Version, 200, _ReasonPhrase}, _Headers, Payload}} ->
            Body = json:decode(iolist_to_binary(Payload)),
            ?assertMatch([_ | _], Body);
        {_, Other} ->
            ct:fail(Other)
    end.

get_zone_record_resource_name(CtConfig) ->
    Request = {endpoint(CtConfig, "/zones/example.com/records/www.example.com"), headers(good)},
    case httpc:request(get, Request, [], []) of
        {ok, {{_Version, 200, _ReasonPhrase}, _Headers, Payload}} ->
            Body = json:decode(iolist_to_binary(Payload)),
            ?assertMatch(
                [
                    #{
                        <<"content">> := <<"example.com.">>,
                        <<"name">> := <<"www.example.com.">>,
                        <<"ttl">> := 120,
                        <<"type">> := <<"CNAME">>
                    }
                ],
                Body
            );
        {_, Other} ->
            ct:fail(Other)
    end.

get_zone_record_resource_name_type(CtConfig) ->
    Request = {
        endpoint(CtConfig, "/zones/example.com/records/www.example.com?type=CNAME"), headers(good)
    },
    case httpc:request(get, Request, [], []) of
        {ok, {{_Version, 200, _ReasonPhrase}, _Headers, Payload}} ->
            Body = json:decode(iolist_to_binary(Payload)),
            ?assertMatch(
                [
                    #{
                        <<"content">> := <<"example.com.">>,
                        <<"name">> := <<"www.example.com.">>,
                        <<"ttl">> := 120,
                        <<"type">> := <<"CNAME">>
                    }
                ],
                Body
            );
        {_, Other} ->
            ct:fail(Other)
    end.

get_zone_record_resource_name_type_non_existing(CtConfig) ->
    Request = {
        endpoint(CtConfig, "/zones/example.com/records/www.example.com?type=A"), headers(good)
    },
    case httpc:request(get, Request, [], []) of
        {ok, {{_Version, 200, _ReasonPhrase}, _Headers, Payload}} ->
            Body = json:decode(iolist_to_binary(Payload)),
            ?assertMatch([], Body);
        {_, Other} ->
            ct:fail(Other)
    end.

get_zone_resources_for_dnssec_signed(CtConfig) ->
    Request = {endpoint(CtConfig, "/zones/example-dnssec0.com"), headers(good)},
    case httpc:request(get, Request, [], []) of
        {ok, {{_Version, 200, _ReasonPhrase}, _Headers, Payload}} ->
            Body = json:decode(iolist_to_binary(Payload)),
            ?assertMatch(
                #{
                    <<"erldns">> :=
                        #{
                            <<"zone">> :=
                                #{
                                    <<"name">> := <<"example-dnssec0.com">>,
                                    <<"records">> := _,
                                    <<"records_count">> := 8,
                                    <<"version">> := <<>>
                                }
                        }
                },
                Body
            );
        {_, Other} ->
            ct:fail(Other)
    end.

endpoint(CtConfig, Path) ->
    Port = proplists:get_value(port, CtConfig),
    "http://localhost:" ++ integer_to_list(Port) ++ Path.

headers(good) ->
    [
        {"accept", "application/json"},
        {"authorization", "basic " ++ base64:encode("username:password")}
    ];
headers(bad_auth) ->
    [
        {"accept", "application/json"},
        {"authorization", "basic " ++ base64:encode("bad_username:bad_password")}
    ].
