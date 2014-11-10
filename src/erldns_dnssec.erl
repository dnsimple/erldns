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

%% @doc Placeholder for eventual DNSSEC implementation.
-module(erldns_dnssec).

-export([handle/2, sign_rrset/3, sign_records/3, dnskey_rrset/1, dnskey_rrset/2]).

-include("erldns.hrl").
-include_lib("dns/include/dns.hrl").

handle(Message, ZoneWithoutRecords) ->
  %lager:debug("Received DNSSEC request: ~p", [Message]),
  {ok, Zone} = erldns_zone_cache:get_zone_with_records(ZoneWithoutRecords#zone.name),

  case sign_message(Message, Zone) of
    {error, ErrorMessage} ->
      lager:error("Cannot sign message: ~p", [ErrorMessage]),
      Message;
    {ok, SignedMessage} ->
      %lager:debug("Signed message: ~p", [SignedMessage]),
      SignedMessage
  end.


%% DNSSEC signing
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
  dnssec:sign_rrset(RRSet, Zone#zone.name, KeyTag, ?DNS_ALG_RSASHA256, SigningKey, []).

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
  Authority = lists:last(SignedZone#zone.authority),
  KSKPublicKey = public_key(SignedZone#zone.key_signing_key),
  KSKDNSKeyData = #dns_rrdata_dnskey{flags = 257, protocol = 3, alg = ?DNS_ALG_RSASHA256, public_key = KSKPublicKey},
  KSKDNSKeyRR = #dns_rr{name = SignedZone#zone.name, type = ?DNS_TYPE_DNSKEY, ttl = Authority#dns_rr.data#dns_rrdata_soa.minimum, data = KSKDNSKeyData},
  dnssec:add_keytag_to_dnskey(KSKDNSKeyRR).

zsk_dnskey_rr(SignedZone) ->
  Authority = lists:last(SignedZone#zone.authority),
  ZSKPublicKey = public_key(SignedZone#zone.zone_signing_key),
  ZSKDNSKeyData = #dns_rrdata_dnskey{flags = 256, protocol = 3, alg = ?DNS_ALG_RSASHA256, public_key = ZSKPublicKey},
  ZSKDNSKeyRR = #dns_rr{name = SignedZone#zone.name, type = ?DNS_TYPE_DNSKEY, ttl = Authority#dns_rr.data#dns_rrdata_soa.minimum, data = ZSKDNSKeyData},
  dnssec:add_keytag_to_dnskey(ZSKDNSKeyRR).

sign_message(Message, Zone) ->
  %Question = lists:last(Message#dns_message.questions),

  case Message#dns_message.answers of
    [] ->
      {ok, Message};
    RRSet ->
      RRSig = sign_rrset(Message, Zone, RRSet),
      {ok, Message#dns_message{answers=Message#dns_message.answers ++ [RRSig]}}
  end.

signed_zone(Zone) ->
  case Zone#zone.zone_signing_key of
    undefined -> erldns_zone_cache:sign_zone(Zone#zone.name);
    _ -> Zone
  end.

public_key(_Key = [E, N, _D]) ->
  [E, N].
