%% Copyright (c) 2012-2015, Aetrion LLC
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

%% @doc Placeholder for eventual DNSSEC implementation.
-module(erldns_dnssec).

-include_lib("dns/include/dns.hrl").
-include("erldns.hrl").

-export([handle/4]).

handle(Message, Zone, Qname, Qtype) ->
  RRSigRecords = handle(Message, Zone, Qname, Qtype, proplists:get_bool(dnssec, erldns_edns:get_opts(Message))),
  Message#dns_message{answers = Message#dns_message.answers ++ RRSigRecords}.

handle(Message, Zone, Qname, Qtype, _DnssecRequested = true) ->
  lager:debug("DNSSEC requested for ~p", [Zone#zone.name]),
  Records = erldns_zone_cache:get_records_by_name(Qname),
  RRSigRecords = lists:filter(erldns_records:match_type(?DNS_TYPE_RRSIG), Records),
  lists:filter(match_type_covered(match_type(Message, Qtype)), RRSigRecords);
handle(_Message, _Zone, _Qname, _Qtype, _DnssecRequest = false) ->
  [].

% Returns the type to match on when looking up the RRSIG records
%
% If there is a CNAME present in the answers then that type must be used for the RRSIG, otherwise
% the Qtype is used.
match_type(Message, Qtype) ->
  case lists:filter(erldns_records:match_type(?DNS_TYPE_CNAME), Message#dns_message.answers) of
    [] -> Qtype;
    _ -> ?DNS_TYPE_CNAME
  end.

match_type_covered(Qtype) ->
  fun(RRSig) ->
      RRSig#dns_rr.data#dns_rrdata_rrsig.type_covered =:= Qtype
  end.
