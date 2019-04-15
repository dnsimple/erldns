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

%% @doc Placeholder for eventual DNSSEC implementation.
-module(erldns_dnssec).

-include_lib("dns/include/dns.hrl").
-include("erldns.hrl").

-export([handle/4]).
-export([key_rrset_signer/2, zone_rrset_signer/2]).
-export([rrsig_for_zone_rrset/2]).
-export([maybe_sign_rrset/3]).

-define(NEXT_DNAME_PART, <<"\000">>).

%% @doc Given a zone and a set of records, return the RRSIG records.
-spec(rrsig_for_zone_rrset(erldns:zone(), [dns:rr()]) -> [dns:rr()]).
rrsig_for_zone_rrset(Zone, RRs) ->
  lists:flatten(lists:map(zone_rrset_signer(Zone#zone.name, RRs), Zone#zone.keysets)).

%% @doc Return a function that can be used to sign the given records using the key signing key.
%% The function accepts a keyset, allowing the zone signing mechanism to iterate through available
%% keysets, applying the key signing key from each keyset.
-spec(key_rrset_signer(dns:name(), [dns:rr()]) -> fun((erldns:keyset()) -> [dns:rr()])).
key_rrset_signer(ZoneName, RRs) ->
  fun(Keyset) ->
      Keytag = Keyset#keyset.key_signing_key_tag,
      Alg = Keyset#keyset.key_signing_alg,
      PrivateKey = Keyset#keyset.key_signing_key,
      Inception = dns:unix_time(Keyset#keyset.inception),
      Expiration = dns:unix_time(Keyset#keyset.valid_until),

      dnssec:sign_rr(RRs, erldns:normalize_name(ZoneName), Keytag, Alg, PrivateKey, [{inception, Inception},{expiration, Expiration}])
  end.

%% @doc Return a function that can be used to sign the given records using the zone signing key.
%% The function accepts a keyset, allowing the zone signing mechanism to iterate through available
%% keysets, applying the zone signing key from each keyset.
-spec(zone_rrset_signer(dns:name(), [dns:rr()]) -> fun((erldns:keyset()) -> [dns:rr()])).
zone_rrset_signer(ZoneName, RRs) ->
  fun(Keyset) ->
      Keytag = Keyset#keyset.zone_signing_key_tag,
      Alg = Keyset#keyset.zone_signing_alg,
      PrivateKey = Keyset#keyset.zone_signing_key,
      Inception = dns:unix_time(Keyset#keyset.inception),
      Expiration = dns:unix_time(Keyset#keyset.valid_until),

      dnssec:sign_rr(RRs, erldns:normalize_name(ZoneName), Keytag, Alg, PrivateKey, [{inception, Inception},{expiration, Expiration}])
  end.

%% @doc This function will potentially sign the given RR set if the following
%% conditions are true:
%%
%% - DNSSEC is requested
%% - The zone is signed
-spec(maybe_sign_rrset(dns:message(), [dns:rr()], erldns:zone()) -> [dns:rr()]).
maybe_sign_rrset(Message, Records, Zone) ->
  case {proplists:get_bool(dnssec, erldns_edns:get_opts(Message)), Zone#zone.keysets}  of
    {true, []} ->
      % DNSSEC requested, zone not signed
      Records;
    {true, _} ->
      % DNSSEC requested, zone signed
      Records ++ erldns_dnssec:rrsig_for_zone_rrset(Zone, Records);
    {false, _} ->
      % DNSSEC not requested
      Records
  end.

%% @doc Apply DNSSEC records to the given message if the zone is signed
%% and DNSSEC is requested.
-spec(handle(dns:message(), erldns:zone(), dns:name(), dns:type()) -> dns:message()).
handle(Message, Zone, Qname, Qtype) ->
  handle(Message, Zone, Qname, Qtype, proplists:get_bool(dnssec, erldns_edns:get_opts(Message)), Zone#zone.keysets).


%%% Internal functions

-spec(handle(dns:message(), erldns:zone(), dns:name(), dns:type(), boolean(), [erldns:keyset()]) -> dns:message()).
handle(Message, _Zone, _Qname, _Qtype, _DnssecRequested = true, []) ->
  % DNSSEC requested, zone unsigned
  Message;
handle(Message, Zone, Qname, _Qtype, _DnssecRequested = true, _Keysets) ->
  % lager:debug("DNSSEC requested (name: ~p)", [Zone#zone.name]),
  Authority = lists:last(Zone#zone.authority),
  Ttl = Authority#dns_rr.data#dns_rrdata_soa.minimum,
  {ok, ZoneWithRecords} = erldns_zone_cache:get_zone_with_records(Zone#zone.name),
  case Message#dns_message.answers of
    [] ->
      ApexRecords = erldns_zone_cache:get_records_by_name(Zone#zone.name),
      ApexRRSigRecords = lists:filter(erldns_records:match_type(?DNS_TYPE_RRSIG), ApexRecords),
      SoaRRSigRecords = lists:filter(erldns_records:match_type_covered(?DNS_TYPE_SOA), ApexRRSigRecords),

      NextDname = erldns:normalize_name(dns:labels_to_dname([?NEXT_DNAME_PART] ++ dns:dname_to_labels(Qname))),
      Types = record_types_for_name(Qname, ZoneWithRecords#zone.records),
      NsecRecords = [#dns_rr{name = Qname, type = ?DNS_TYPE_NSEC, ttl = Ttl, data = #dns_rrdata_nsec{next_dname = NextDname, types = Types}}],
      NsecRRSigRecords = rrsig_for_zone_rrset(Zone, NsecRecords),

      erldns_records:rewrite_soa_ttl(sign_unsigned(Message#dns_message{ad = true, rc = ?DNS_RCODE_NOERROR, authority = Message#dns_message.authority ++ NsecRecords ++ SoaRRSigRecords ++ NsecRRSigRecords}, Zone));
    _ ->
      AnswerSignatures = find_rrsigs(ZoneWithRecords#zone.records, Message#dns_message.answers),
      AuthoritySignatures = find_rrsigs(ZoneWithRecords#zone.records, Message#dns_message.authority),
      erldns_records:rewrite_soa_ttl(sign_unsigned(Message#dns_message{ad = true, answers = Message#dns_message.answers ++ AnswerSignatures, authority = Message#dns_message.authority ++ AuthoritySignatures}, Zone))
  end;
handle(Message, _Zone, _Qname, _Qtype, _DnssecRequest = false, _) ->
  Message.

-spec(find_rrsigs([dns:rr()], [dns:rr()]) -> [dns:rr()]).
find_rrsigs(ZoneRecords, MessageRecords) ->
  NamesAndTypes = lists:usort(lists:map(fun(RR) -> {RR#dns_rr.name, RR#dns_rr.type} end, MessageRecords)),
  lists:flatten(
    lists:map(
      fun({Name, Type}) ->
          NamedRRSigs = lists:filter(erldns_records:match_name_and_type(Name, ?DNS_TYPE_RRSIG), ZoneRecords),
          lists:filter(erldns_records:match_type_covered(Type), NamedRRSigs)
      end, NamesAndTypes)).

-spec(sign_unsigned(dns:message(), erldns:zone()) -> dns:message()).
sign_unsigned(Message, Zone) ->
  UnsignedAnswers = find_unsigned_records(Message#dns_message.answers),
  AnswerSignatures = erldns_dnssec:rrsig_for_zone_rrset(Zone, UnsignedAnswers),
  Message#dns_message{answers = Message#dns_message.answers ++ AnswerSignatures}.

-spec(find_unsigned_records([dns:rr()]) -> [dns:rr()]).
find_unsigned_records(Records) ->
  lists:filter(
    fun(RR) ->
        (RR#dns_rr.type =/= ?DNS_TYPE_RRSIG) and (lists:filter(erldns_records:match_name_and_type(RR#dns_rr.name, ?DNS_TYPE_RRSIG), Records) =:= [])
    end, Records).

record_types_for_name(Name, Records) ->
  RecordsAtName = lists:filter(erldns_records:match_name(Name), Records),
  TypesCovered = lists:map(fun(RR) -> RR#dns_rr.type end, RecordsAtName),
  lists:usort(TypesCovered ++ [?DNS_TYPE_RRSIG, ?DNS_TYPE_NSEC]).


