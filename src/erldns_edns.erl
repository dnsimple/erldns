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

%% @doc Placeholder for eventual EDNS0 implementation.
-module(erldns_edns).

-include_lib("dns/include/dns_records.hrl").

-export([handle/2, get_opts/1]).

handle(Message, Zone) ->
  handle_opts(Message, Zone, Message#dns_message.additional).

handle_opts(Message, _Zone, []) ->
  Message;
handle_opts(Message, Zone, [RR|Rest]) when is_record(RR, dns_optrr) ->
  NewMessage = case RR#dns_optrr.dnssec of
                 true -> erldns_dnssec:handle(Message, Zone);
                 false -> Message
               end,
  handle_opts(NewMessage, Zone, Rest);
handle_opts(Message, Zone, [_|Rest]) ->
  handle_opts(Message, Zone, Rest).

% @doc Get a property list of EDNS0 options.
%
% Supported options are:
%
% * {dnssec, true}
-spec get_opts(dns:message()) -> [proplists:property()].
get_opts(Message) ->
  get_opts(Message#dns_message.additional, []).

get_opts([], Opts) ->
  Opts;
get_opts([RR|Rest], Opts) when is_record(RR, dns_rr) ->
  get_opts(Rest, Opts);
get_opts([RR|Rest], Opts) when is_record(RR, dns_optrr) ->
  get_opts(Rest, case RR#dns_optrr.dnssec of
    true -> Opts ++ [{dnssec, true}];
    false -> Opts
  end).
