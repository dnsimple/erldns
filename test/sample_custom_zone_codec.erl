-module(sample_custom_zone_codec).
-moduledoc "Sample custom zone parser.".
-behaviour(erldns_zone_codec).

-include_lib("dns_erlang/include/dns.hrl").

-export([decode/1, encode/1]).

-define(DNS_TYPE_SAMPLE, 40000).

decode(#{~"name" := Name, ~"type" := ~"SAMPLE", ~"ttl" := Ttl, ~"data" := Data}) ->
    #dns_rr{
        name = Name,
        type = ?DNS_TYPE_SAMPLE,
        data = maps:get(~"dname", Data),
        ttl = Ttl
    };
decode(_) ->
    not_implemented.

encode(#dns_rr{name = Name, type = ?DNS_TYPE_SAMPLE, ttl = Ttl, data = Data}) ->
    #{
        ~"name" => erlang:iolist_to_binary(io_lib:format("~s.", [Name])),
        ~"type" => ~"SAMPLE",
        ~"ttl" => Ttl,
        ~"content" => erlang:iolist_to_binary(io_lib:format("~s", [Data]))
    };
encode(_) ->
    not_implemented.
