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

-export([handle/1]).

handle(Message) ->
    handle_opts(Message, Message#dns_message.additional).

handle_opts(Message, []) ->
    Message;
handle_opts(Message, [RR|Rest]) when is_record(RR, dns_optrr) ->
    NewMessage = case RR#dns_optrr.dnssec of
                     true -> erldns_dnssec:handle(Message);
                     false -> Message
                 end,
    handle_opts(NewMessage, Rest);
handle_opts(Message, [_|Rest]) ->
    handle_opts(Message, Rest).
