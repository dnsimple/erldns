-module(sample_custom_zone_pipe).
-moduledoc "Sample zone pipe that decodes and encodes a custom record type.".
-behaviour(erldns_zone_pipeline).

-include_lib("dns_erlang/include/dns.hrl").

-export([decode_record/3, encode/1]).

-define(DNS_TYPE_SAMPLE, 40000).

decode_record(_, #{~"type" := ~"SAMPLE"} = Json, _Opts) ->
    #{~"name" := Name, ~"ttl" := Ttl, ~"data" := #{~"dname" := Dname}} = Json,
    #dns_rr{name = Name, type = ?DNS_TYPE_SAMPLE, data = Dname, ttl = Ttl};
decode_record(_, Entry, _Opts) ->
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
