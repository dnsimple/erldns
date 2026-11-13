-module(sample_custom_zone_pipe).
-moduledoc "Sample zone pipe that decodes and encodes a custom record type.".
-behaviour(erldns_zone_pipeline).

-include_lib("dns_erlang/include/dns.hrl").

-export([call/2, encode/1]).

-define(DNS_TYPE_SAMPLE, 40000).

call(Entries, _Opts) ->
    [decode(Entry) || Entry <- Entries].

decode(#{~"name" := Name, ~"type" := ~"SAMPLE", ~"ttl" := Ttl, ~"data" := Data}) ->
    #dns_rr{name = Name, type = ?DNS_TYPE_SAMPLE, data = maps:get(~"dname", Data), ttl = Ttl};
decode(Entry) ->
    Entry.

encode(#dns_rr{name = Name, type = ?DNS_TYPE_SAMPLE, ttl = Ttl, data = Data}) ->
    #{
        ~"name" => erlang:iolist_to_binary(io_lib:format("~s.", [Name])),
        ~"type" => ~"SAMPLE",
        ~"ttl" => Ttl,
        ~"content" => Data
    };
encode(_) ->
    not_implemented.
