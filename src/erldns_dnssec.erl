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

-export([handle/2]).

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

sign_message(Message, Zone) ->
  case Message#dns_message.answers of
    [] ->
      {ok, Message};
    RRSet ->
      Question = lists:last(Message#dns_message.questions),
      SignedZone = signed_zone(Zone),
      [SigningKey, DNSKey] = signing_key(SignedZone, Question#dns_query.type),
      KeyTag = DNSKey#dns_rr.data#dns_rrdata_dnskey.key_tag,
      RRSig = dnssec:sign_rrset(RRSet, Zone#zone.name, KeyTag, ?DNS_ALG_RSASHA256, SigningKey, []),
      {ok, Message#dns_message{answers=Message#dns_message.answers ++ [RRSig]}}
  end.

signing_key(SignedZone, ?DNS_TYPE_DNSKEY_NUMBER) -> [SignedZone#zone.key_signing_key, find_dnskey(SignedZone, 257)];
signing_key(SignedZone, _) -> [SignedZone#zone.zone_signing_key, find_dnskey(SignedZone, 256)].


signed_zone(Zone) ->
  case Zone#zone.zone_signing_key of
    undefined -> erldns_zone_cache:sign_zone(Zone#zone.name);
    _ -> Zone
  end.

find_dnskey(Zone, KeyType) ->
  case lists:filter(fun(R) -> apply(erldns_records:match_type(?DNS_TYPE_DNSKEY), [R]) end, Zone#zone.records) of
    [] -> not_found;
    DNSKeys ->
      case lists:filter(fun(R) -> apply(erldns_records:match_dnskey_type(KeyType), [R]) end, DNSKeys) of
        [] -> not_found;
        DNSKeysForType -> lists:last(DNSKeysForType)
      end
  end.
