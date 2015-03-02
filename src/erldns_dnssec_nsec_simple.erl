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

%% @doc Simple NSEC
-module(erldns_dnssec_nsec_simple).

-include_lib("dns/include/dns.hrl").
-include("erldns.hrl").

-export([include_nsec/5]).

include_nsec(Message, Qname, Qtype, ZoneWithRecords, _CnameChain) ->
  include_nsec(Message, Qname, Qtype, ZoneWithRecords, _CnameChain, Message#dns_message.rc).

include_nsec(Message, Qname, Qtype, ZoneWithRecords, _CnameChain, _Rcode = ?DNS_RCODE_NXDOMAIN) ->
  include_nsec_nxdomain(Message, Qname, Qtype, ZoneWithRecords, _CnameChain, lists:filter(erldns_records:match_name(Qname), ZoneWithRecords#zone.records));
include_nsec(Message, Qname, Qtype, ZoneWithRecords, _CnameChain, _Rcode = ?DNS_RCODE_NOERROR) ->
  include_nsec_noerror(Message, Qname, Qtype, ZoneWithRecords, _CnameChain, lists:filter(erldns_records:match_name_and_type(Qname, Qtype), ZoneWithRecords#zone.records), lists:filter(erldns_records:match_type(Qtype), ZoneWithRecords#zone.records));
include_nsec(Message, _Qname, _Qtype, _ZoneWithRecords, _CnameChain, _Rcode) ->
  Message.


include_nsec_nxdomain(Message, Qname, _Qtype, ZoneWithRecords, _CnameChain, _NameMatchedRecords = []) ->
  Types = [?DNS_TYPE_NSEC, ?DNS_TYPE_RRSIG],
  NsecData = #dns_rrdata_nsec{next_dname = next_dname(Qname), types = Types},
  NSECRecords = [#dns_rr{name = Qname, type = ?DNS_TYPE_NSEC, ttl = nsec_ttl(ZoneWithRecords), data = NsecData}],
  Message#dns_message{authority = Message#dns_message.authority ++ NSECRecords};
include_nsec_nxdomain(Message, _Qname, _Qtype, _ZoneWithRecords, _CnameChain, _NameMatchedRecords) ->
  Message.


include_nsec_noerror(Message, Qname, Qtype, ZoneWithRecords, _CnameChain, _NameAndTypeMatchedRecords = [], TypeMatchedRecords) ->
  Records = lists:filter(erldns_records:match_name(Qname), ZoneWithRecords#zone.records),
  AdditionalTypes = lists:usort(lists:map(fun(RR) -> RR#dns_rr.type end, Records)),
  Types = AdditionalTypes ++ [?DNS_TYPE_NSEC, ?DNS_TYPE_RRSIG],
  NsecData = #dns_rrdata_nsec{next_dname = next_dname(Qname), types = Types},
  NSECRecords = [#dns_rr{name = Qname, type = ?DNS_TYPE_NSEC, ttl = nsec_ttl(ZoneWithRecords), data = NsecData}],

  case TypeMatchedRecords of
    [] ->
      case Qtype of
        ?DNS_TYPE_ANY -> Message#dns_message{answers = Message#dns_message.answers ++ NSECRecords};
        ?DNS_TYPE_DNSKEY -> Message;
        _ -> Message#dns_message{authority = Message#dns_message.authority ++ NSECRecords}
      end;
    _ ->
      case lists:filter(erldns_records:match_name_and_type(Qname, ?DNS_TYPE_CNAME), ZoneWithRecords#zone.records) of
        [] ->
          case lists:filter(fun(RR) -> erldns_records:dname_match(Qname, RR#dns_rr.name) end, TypeMatchedRecords) of
            [] -> Message#dns_message{authority = Message#dns_message.authority ++ NSECRecords};
            _WildcardMatches -> Message
          end;
        _ ->
          Message
      end
  end;
include_nsec_noerror(Message, _Qname, _Qtype, _ZoneWithRecords, _CnameChain, _NameAndTypeMatchedRecords, _TypeMatchedRecords) ->
  Message.

next_dname(Qname) ->
  dns:labels_to_dname([<<"\003">>] ++ dns:dname_to_labels(Qname)).

nsec_ttl(Zone) ->
  Soa = lists:last(Zone#zone.authority),
  Soa#dns_rr.data#dns_rrdata_soa.minimum.
