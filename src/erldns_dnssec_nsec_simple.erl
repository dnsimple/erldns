-module(erldns_dnssec_nsec_simple).

-include_lib("dns/include/dns.hrl").
-include("erldns.hrl").

-export([include_nsec/5]).

include_nsec(Message, Qname, Qtype, ZoneWithRecords, _CnameChain) ->
  include_nsec(Message, Qname, Qtype, ZoneWithRecords, _CnameChain, Message#dns_message.rc).

include_nsec(Message, Qname, Qtype, ZoneWithRecords, _CnameChain, _Rcode = ?DNS_RCODE_NXDOMAIN) ->
  lager:debug("Zone present, but response is NXDOMAIN"),
  include_nsec_nxdomain(Message, Qname, Qtype, ZoneWithRecords, _CnameChain, lists:filter(erldns_records:match_name(Qname), ZoneWithRecords#zone.records));
include_nsec(Message, Qname, Qtype, ZoneWithRecords, _CnameChain, _Rcode = ?DNS_RCODE_NOERROR) ->
  lager:debug("Zone present, response code is NOERROR"),
  include_nsec_noerror(Message, Qname, Qtype, ZoneWithRecords, _CnameChain, lists:filter(erldns_records:match_name_and_type(Qname, Qtype), ZoneWithRecords#zone.records), lists:filter(erldns_records:match_type(Qtype), ZoneWithRecords#zone.records));
include_nsec(Message, _Qname, _Qtype, _ZoneWithRecords, _CnameChain, Rcode) ->
  lager:debug("Rcode was ~p", [Rcode]),
  Message.


include_nsec_nxdomain(Message, Qname, _Qtype, ZoneWithRecords, _CnameChain, _NameMatchedRecords = []) ->
  lager:debug("Name and type not present"),
  Types = [?DNS_TYPE_NSEC, ?DNS_TYPE_RRSIG],
  NsecData = #dns_rrdata_nsec{next_dname = next_dname(Qname), types = Types},
  NSECRecords = [#dns_rr{name = Qname, type = ?DNS_TYPE_NSEC, ttl = nsec_ttl(ZoneWithRecords), data = NsecData}],
  Message#dns_message{authority = Message#dns_message.authority ++ NSECRecords};
include_nsec_nxdomain(Message, _Qname, _Qtype, _ZoneWithRecords, _CnameChain, _NameMatchedRecords) ->
  lager:debug("Name is present, but does not match qtype"),
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
        ?DNS_TYPE_ANY ->
          lager:debug("Name is present, type is ANY"),
          Message#dns_message{answers = Message#dns_message.answers ++ NSECRecords};
        ?DNS_TYPE_DNSKEY ->
          lager:debug("Name is present, type is DNSKEY"),
          Message;
        _ ->
          lager:debug("Name is present, type is not"),
          Message#dns_message{authority = Message#dns_message.authority ++ NSECRecords}
      end;
    _ ->
      lager:debug("Name and type do not match, but name is present with another type"),
      case lists:any(erldns_records:match_name_and_type(Qname, ?DNS_TYPE_CNAME), ZoneWithRecords#zone.records) of
        true ->
          lager:debug("Other type is CNAME"),
          Message;
        false ->
          Message#dns_message{authority = Message#dns_message.authority ++ NSECRecords}
      end
  end;
include_nsec_noerror(Message, _Qname, _Qtype, _ZoneWithRecords, _CnameChain, _NameAndTypeMatchedRecords, _TypeMatchedRecords) ->
  lager:debug("Name and type are present"),
  Message.

next_dname(Qname) ->
  dns:labels_to_dname([<<"\003">>] ++ dns:dname_to_labels(Qname)).

nsec_ttl(Zone) ->
  Soa = lists:last(Zone#zone.authority),
  Soa#dns_rr.data#dns_rrdata_soa.minimum.
