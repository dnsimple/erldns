%% Copyright (c) 2012-2020, DNSimple Corporation
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

-module(erldns_axfr).
-moduledoc """
Implementation of AXFR with IP address whitelisting required.

### AXFR Support

AXFR zone transfers are not currently implemented. The current "implementation" is just a stub.
""".

-include_lib("dns_erlang/include/dns.hrl").

-behaviour(erldns_pipeline).

-export([call/2]).
-export([is_enabled/2]).

-doc "`c:erldns_pipeline:call/2` callback.".
-spec call(dns:message(), erldns_pipeline:opts()) -> dns:message().
call(#dns_message{questions = Questions} = Msg, _) ->
    %% If the message is an AXFR request then append the SOA record.
    case lists:any(fun(#dns_query{type = T}) -> T =:= ?DNS_TYPE_AXFR end, Questions) of
        true ->
            append_soa(Msg, Msg#dns_message.answers);
        false ->
            Msg
    end.

-doc "Determine if AXFR is enabled for the given request host.".
-spec is_enabled(_, _) -> boolean().
is_enabled(Host, Metadata) ->
    lists:any(
        fun(MetadataRow) ->
            [_Id, _DomainId, Kind, Content] = MetadataRow,
            {ok, AllowedAddress} = inet:parse_address(binary_to_list(Content)),
            AllowedAddress =:= Host andalso Kind =:= <<"axfr">>
        end,
        Metadata
    ).

append_soa(Message, []) ->
    Message;
append_soa(Message, [#dns_rr{type = ?DNS_TYPE_SOA} = Answer | _Rest]) ->
    Answers = lists:flatten(Message#dns_message.answers ++ [Answer]),
    Message#dns_message{anc = length(Answers), answers = Answers};
append_soa(Message, [_Answer | Rest]) ->
    append_soa(Message, Rest).
