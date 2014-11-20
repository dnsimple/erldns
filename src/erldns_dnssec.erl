%% Copyright (c) 2012-2014, Aetrion LLC
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

%% @doc DNSSEC support methods.
-module(erldns_dnssec).

-export([sign_message/5, sign_message/6, sign_wildcard_message/4, sign_wildcard_message/5, sign_rrset/3, sign_records/3, dnskey_rrset/1, dnskey_rrset/2]).

-include("erldns.hrl").
-include_lib("dns/include/dns.hrl").

sign_message(Message, _Qname, _Qtype, Zone, AnswerRecords) ->
  AnswersRRSig = [erldns_dnssec:sign_rrset(Message, Zone, AnswerRecords)],
  Message#dns_message{answers = Message#dns_message.answers ++ AnswersRRSig}.

sign_message(Message, _Qname, _Qtype, Zone, _AnswerRecords = [], AuthorityRecords) ->
  Authority = lists:last(Zone#zone.authority),
  AuthoritiesRRSig = lists:map(rewrite_rrsig_ttl(Authority), [erldns_dnssec:sign_rrset(Message, Zone, AuthorityRecords)]),
  Message#dns_message{authority = Message#dns_message.authority ++ AuthoritiesRRSig}.

sign_wildcard_message(Message, Qname, Zone, AnswerRecords) ->
  lager:debug("Sign wildcard message (Qname = ~p)", [Qname]),
  lager:debug("Answers: ~p", [AnswerRecords]),
  AnswersRRSig = lists:map(erldns_records:replace_name(Qname), [erldns_dnssec:sign_rrset(Message, Zone, AnswerRecords)]),
  Message#dns_message{answers = Message#dns_message.answers ++ AnswersRRSig, authority = Message#dns_message.authority}.

sign_wildcard_message(Message, Qname, Zone, AnswerRecords, FollowedCname) ->
  lager:debug("Sign wildcard message (Qname = ~p, CNAME = ~p)", [Qname, FollowedCname]),
  AnswersRRSig = lists:map(erldns_records:replace_name(Qname), [erldns_dnssec:sign_rrset(Message, Zone, AnswerRecords)]),
  Message#dns_message{answers = Message#dns_message.answers ++ AnswersRRSig, authority = Message#dns_message.authority}.


sign_records(Message, Zone, Records) ->
  Answers = Message#dns_message.answers ++ Records,
  case proplists:get_bool(dnssec, erldns_edns:get_opts(Message)) of
    true -> Answers ++ [erldns_dnssec:sign_rrset(Message, Zone, Records)];
    false -> Answers
  end.

%% @doc Signs an RR set and returns a single RRSIG record.
-spec sign_rrset(dns:message(), erldns:zone(), [dns:rr()]) -> dns:rr().
sign_rrset(Message, Zone, RRSet) ->
  %lager:debug("Sign RRSet: ~p", [RRSet]),
  SignedZone = signed_zone(Zone),
  [SigningKey, KeyTag] = key_and_tag(Message, SignedZone),
  dnssec:sign_rrset(lists:flatten([RRSet]), Zone#zone.name, KeyTag, ?DNS_ALG_RSASHA256, SigningKey, []).




key_and_tag(Message, SignedZone) ->
  Question = lists:last(Message#dns_message.questions),

  [KSKDNSKey, ZSKDNSKey] = dnskey_rrset(SignedZone),

  case Question#dns_query.type of
    ?DNS_TYPE_DNSKEY_NUMBER -> [SignedZone#zone.key_signing_key, KSKDNSKey#dns_rr.data#dns_rrdata_dnskey.key_tag];
    _ -> [SignedZone#zone.zone_signing_key, ZSKDNSKey#dns_rr.data#dns_rrdata_dnskey.key_tag]
  end.

dnskey_rrset(SignedZone) ->
  [ksk_dnskey_rr(SignedZone), zsk_dnskey_rr(SignedZone)].

dnskey_rrset(Message, Zone) ->
  case proplists:get_bool(dnssec, erldns_edns:get_opts(Message)) of
    true -> dnskey_rrset(Zone);
    false -> []
  end.

ksk_dnskey_rr(SignedZone) ->
  dnskey_rr(SignedZone, 257).

zsk_dnskey_rr(SignedZone) ->
  dnskey_rr(SignedZone, 256).

dnskey_rr(SignedZone, Flags) ->
  case lists:filter(erldns_records:match_dnskey_type(Flags), SignedZone#zone.records) of
    [] ->
      Authority = lists:last(SignedZone#zone.authority),
      PublicKey = public_key(SignedZone#zone.zone_signing_key),
      DNSKeyData = #dns_rrdata_dnskey{flags = Flags, protocol = 3, alg = ?DNS_ALG_RSASHA256, public_key = PublicKey},
      DNSKeyRR = #dns_rr{name = SignedZone#zone.name, type = ?DNS_TYPE_DNSKEY, ttl = Authority#dns_rr.data#dns_rrdata_soa.minimum, data = DNSKeyData},
      dnssec:add_keytag_to_dnskey(DNSKeyRR);
    Records ->
      % There should only be one key of the type indicated by Flags
      % In the future this may change if we support multiple zone signing keys
      lists:last(Records)
  end.

signed_zone(Zone) ->
  case Zone#zone.zone_signing_key of
    undefined -> erldns_zone_cache:sign_zone(Zone#zone.name);
    _ -> Zone
  end.

public_key(_Key = [E, N, _D]) ->
  [E, N].

rewrite_rrsig_ttl(Authority) ->
  fun(R) ->
      R#dns_rr{ttl = Authority#dns_rr.data#dns_rrdata_soa.minimum}
  end.
