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
-export([key_rrset_signer/2, zone_rrset_signer/2]).
-export([rrsig_for_zone_rrset/2]).

%% @doc Apply DNSSEC records to the given message if the zone is signed
%% and DNSSEC is requested.
-spec(handle(dns:message(), erldns:zone(), dns:name(), dns:type()) -> dns:message()).
handle(Message, Zone, Qname, Qtype) ->
  handle(Message, Zone, Qname, Qtype, proplists:get_bool(dnssec, erldns_edns:get_opts(Message)), Zone#zone.keysets).

handle(Message, _Zone, _Qname, _Qtype, _DnssecRequested = true, []) ->
  % DNSSEC requested, zone unsigned
  Message;
handle(Message, Zone, Qname, _Qtype, _DnssecRequested = true, _Keysets) ->
  lager:debug("DNSSEC requested for ~p", [Zone#zone.name]),
  Authority = lists:last(Zone#zone.authority),
  Ttl = Authority#dns_rr.data#dns_rrdata_soa.minimum,
  {ok, ZoneWithRecords} = erldns_zone_cache:get_zone_with_records(Zone#zone.name),
  case Message#dns_message.answers of
    [] ->
      ApexRecords = erldns_zone_cache:get_records_by_name(Zone#zone.name),
      ApexRRSigRecords = lists:filter(erldns_records:match_type(?DNS_TYPE_RRSIG), ApexRecords),
      SoaRRSigRecords = lists:filter(match_type_covered(?DNS_TYPE_SOA), ApexRRSigRecords),

      NextDname = dns:labels_to_dname([<<"\000">>] ++ dns:dname_to_labels(Qname)),
      Types = lists:usort(lists:map(fun(RR) -> RR#dns_rr.type end, ZoneWithRecords#zone.records) ++ [?DNS_TYPE_RRSIG, ?DNS_TYPE_NSEC]),
      NsecRecords = [#dns_rr{name = Qname, type = ?DNS_TYPE_NSEC, ttl = Ttl, data = #dns_rrdata_nsec{next_dname = NextDname, types = Types}}],
      NsecRRSigRecords = rrsig_for_zone_rrset(Zone, NsecRecords),

      Message#dns_message{ad = true, authority = Message#dns_message.authority ++ NsecRecords ++ SoaRRSigRecords ++ NsecRRSigRecords};
    _ ->
      RRSigs = find_rrsigs(Message, ZoneWithRecords#zone.records),
      Message#dns_message{ad = true, answers = Message#dns_message.answers ++ RRSigs}
  end;
handle(Message, _Zone, _Qname, _Qtype, _DnssecRequest = false, _) ->
  Message.

-spec(find_rrsigs(dns:message(), [dns:rr()]) -> [dns:rr()]).
find_rrsigs(Message, Records) ->
  NamesAndTypes = lists:usort(lists:map(fun(RR) -> {RR#dns_rr.name, RR#dns_rr.type} end, Message#dns_message.answers)),
  lists:flatten(
    lists:map(
      fun({Name, Type}) ->
          NamedRRSigs = lists:filter(erldns_records:match_name_and_type(Name, ?DNS_TYPE_RRSIG), Records),
          lists:filter(match_type_covered(Type), NamedRRSigs)
      end, NamesAndTypes)).

-spec(match_type_covered(dns:type()) -> fun((dns:rr()) -> boolean())).
match_type_covered(Qtype) ->
  fun(RRSig) ->
      RRSig#dns_rr.data#dns_rrdata_rrsig.type_covered =:= Qtype
  end.

rrsig_for_zone_rrset(Zone, RRs) ->
  lists:flatten(lists:map(zone_rrset_signer(Zone#zone.name, RRs), Zone#zone.keysets)).

-spec(key_rrset_signer(dns:name(), [dns:rr()]) -> fun((erldns:keyset()) -> dns:rr())).
key_rrset_signer(ZoneName, RRs) ->
  fun(Keyset) ->
      Keytag = Keyset#keyset.key_signing_key_tag,
      Alg = Keyset#keyset.key_signing_alg,
      PrivateKey = Keyset#keyset.key_signing_key,
      Inception = dns:unix_time(Keyset#keyset.inception),
      Expiration = dns:unix_time(Keyset#keyset.valid_until),

      dnssec:sign_rr(RRs, erldns:normalize_name(ZoneName), Keytag, Alg, PrivateKey, [{inception, Inception},{expiration, Expiration}])
  end.

zone_rrset_signer(ZoneName, RRs) ->
  fun(Keyset) ->
      Keytag = Keyset#keyset.zone_signing_key_tag,
      Alg = Keyset#keyset.zone_signing_alg,
      PrivateKey = Keyset#keyset.zone_signing_key,
      Inception = dns:unix_time(Keyset#keyset.inception),
      Expiration = dns:unix_time(Keyset#keyset.valid_until),

      dnssec:sign_rr(RRs, erldns:normalize_name(ZoneName), Keytag, Alg, PrivateKey, [{inception, Inception},{expiration, Expiration}])
  end.
