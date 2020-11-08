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

%% @doc Implementation of AXFR with IP address whitelisting required.
-module(erldns_axfr).

-include_lib("dns_erlang/include/dns.hrl").

-export([is_enabled/2, optionally_append_soa/1]).

%% Determine if AXFR is enabled for the given request host.
is_enabled(Host, Metadata) ->
  MatchingMetadata = lists:filter(
                       fun(MetadataRow) ->
                           [_Id, _DomainId, Kind, Content] = MetadataRow,
                           {ok, AllowedAddress} = inet_parse:address(binary_to_list(Content)),
                           AllowedAddress =:= Host andalso Kind =:= <<"axfr">>
                       end, Metadata),
  length(MatchingMetadata) > 0.

%% If the message is an AXFR request then append the SOA record.
optionally_append_soa(Message) ->
  optionally_append_soa(Message, Message#dns_message.questions).
optionally_append_soa(Message, []) ->
  Message;
optionally_append_soa(Message, [Q|Rest]) ->
  case Q#dns_query.type of 
    ?DNS_TYPE_AXFR_NUMBER -> append_soa(Message, Message#dns_message.answers);
    _ -> optionally_append_soa(Message, Rest)
  end.

append_soa(Message, []) ->
  Message;
append_soa(Message, [Answer|Rest]) ->
  append_soa(Message, Answer#dns_rr.type, Answer, Rest).
append_soa(Message, ?DNS_TYPE_SOA_NUMBER, Answer, _) ->
  Answers = lists:flatten(Message#dns_message.answers ++ [Answer]),
  Message#dns_message{anc = length(Answers), answers = Answers};
append_soa(Message, _, _, []) ->
  Message;
append_soa(Message, _, _, [Answer|Rest]) ->
  append_soa(Message, Answer#dns_rr.type, Answer, Rest).
