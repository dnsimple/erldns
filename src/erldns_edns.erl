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

%% @doc EDNS0 implementation.
-module(erldns_edns).

-include_lib("dns_erlang/include/dns_records.hrl").

-export([get_opts/1]).

%% @doc Get a property list of EDNS0 options.
%%
%% Supported options are:
%%
%% * {dnssec, true}
-spec get_opts(dns:message()) -> [proplists:property()].
get_opts(Message) ->
  get_opts(Message#dns_message.additional, []).

-spec get_opts([dns:rr()|dns:optrr()], [proplists:property()]) -> [proplists:property()].
get_opts([], Opts) ->
  Opts;
get_opts([RR|Rest], Opts) when is_record(RR, dns_rr) ->
  get_opts(Rest, Opts);
get_opts([RR|Rest], Opts) when is_record(RR, dns_optrr) and RR#dns_optrr.dnssec ->
  get_opts(Rest, Opts ++ [{dnssec, true}]);
get_opts([_RR|Rest], Opts) ->
  get_opts(Rest, Opts).
