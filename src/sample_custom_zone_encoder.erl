%% Copyright (c) 2012-2018, DNSimple Corporation
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

%% @doc Sample custom encoder.
-module(sample_custom_zone_encoder).

-include_lib("dns_erlang/include/dns.hrl").
-include("erldns.hrl").

-export([encode_record/1]).

-define(DNS_TYPE_SAMPLE, 40000).

encode_record({dns_rr, Name, _, ?DNS_TYPE_SAMPLE, Ttl, Data}) ->
  lager:debug("Encoding SAMPLE record"),
  [
   {<<"name">>, erlang:iolist_to_binary(io_lib:format("~s.", [Name]))},
   {<<"type">>, <<"SAMPLE">>},
   {<<"ttl">>, Ttl},
   {<<"content">>, erlang:iolist_to_binary(io_lib:format("~s", [Data]))}
  ];
encode_record(_) ->
  lager:debug("Could not encode record"),
  [].
