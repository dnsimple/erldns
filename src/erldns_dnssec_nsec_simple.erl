-module(erldns_dnssec_nsec_simple).

-include_lib("dns/include/dns.hrl").
-include("erldns.hrl").

-export([include_nsec/5]).

include_nsec(Message, Qname, Qtype, ZoneWithRecords, _CnameChain) ->
  Soa = lists:last(ZoneWithRecords#zone.authority),
  SoaMinimumTtl = Soa#dns_rr.data#dns_rrdata_soa.minimum,
  NextDname = dns:labels_to_dname([<<"\003">>] ++ dns:dname_to_labels(Qname)),

  case Message#dns_message.rc of
    ?DNS_RCODE_NXDOMAIN ->
      lager:debug("Zone present, but response is NXDOMAIN"),
      case lists:any(erldns_records:match_name(Qname), ZoneWithRecords#zone.records) of
        true ->
          lager:debug("Name is present, but does not match qtype"),
          Message;
        false ->
          lager:debug("Name and type not present"),

          Types = [?DNS_TYPE_NSEC, ?DNS_TYPE_RRSIG],

          NSECRecords = [#dns_rr{name = Qname, type = ?DNS_TYPE_NSEC, ttl = SoaMinimumTtl, data = #dns_rrdata_nsec{next_dname = NextDname, types = Types}}],

          Message#dns_message{authority = Message#dns_message.authority ++ NSECRecords}
      end;
    ?DNS_RCODE_NOERROR ->
      lager:debug("Zone present, response code is NOERROR"),
      case lists:any(erldns_records:match_type(Qtype), ZoneWithRecords#zone.records) of
        true ->
          lager:debug("Name and type are present"),
          Message;
        false ->
          lager:debug("Name is present, type is not"),

          Records = lists:filter(erldns_records:match_name(Qname), ZoneWithRecords#zone.records),
          AdditionalTypes = lists:usort(lists:map(fun(RR) -> RR#dns_rr.type end, Records)),
          Types = AdditionalTypes ++ [?DNS_TYPE_NSEC, ?DNS_TYPE_RRSIG],
          NSECRecords = [#dns_rr{name = Qname, type = ?DNS_TYPE_NSEC, ttl = SoaMinimumTtl, data = #dns_rrdata_nsec{next_dname = NextDname, types = Types}}],

          case Qtype of
            ?DNS_TYPE_ANY ->
              Message#dns_message{answers = Message#dns_message.answers ++ NSECRecords};
            _ ->
              Message#dns_message{authority = Message#dns_message.authority ++ NSECRecords}
          end
      end;
    Rcode ->
      lager:debug("Rcode was ~p", [Rcode]),
      Message
  end.
