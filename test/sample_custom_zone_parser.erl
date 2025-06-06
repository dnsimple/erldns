%% Copyright (c) 2012-2020, DNSimple Corporation
%%
%% Permission to use, copy, modify, and/or distribute this software for any
%% purpose with or without fee is hereby granted, provided that the above
%% copyright notice and this permission notice appear in all copies.
%%
%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
%% WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
%% MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
%% ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
%% WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
%% ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
%% OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

-module(sample_custom_zone_parser).
-moduledoc "Sample custom zone parser.".

-include_lib("dns_erlang/include/dns.hrl").

-include("erldns.hrl").

-export([json_record_to_erlang/1]).

-define(DNS_TYPE_SAMPLE, 40000).

json_record_to_erlang(#{~"name" := Name, ~"type" := ~"SAMPLE", ~"ttl" := Ttl, ~"data" := Data}) ->
    #dns_rr{
        name = Name,
        type = ?DNS_TYPE_SAMPLE,
        data = maps:get(~"dname", Data),
        ttl = Ttl
    };
json_record_to_erlang(_) ->
    not_implemented.
