-module(erldns_edns_max_payload_size).
-moduledoc """
Set the UDP payload size in answers.

DNS over UDP has traditionally been limited to 512 bytes per message. However, with the introduction
of EDNS (Extension Mechanisms for DNS), clients can specify larger UDP payload sizes through the OPT
   RR (Resource Record) in the additional section of the DNS message.

In Erldns, we've implemented a strict enforcement of UDP payload sizes to ensure compatibility and
prevent potential issues:

1. **Minimum Size**: We enforce a minimum UDP payload size of 512 bytes (`?MIN_PACKET_SIZE`),
    which is the traditional DNS UDP message size limit.
2. **Maximum Size**: We enforce a maximum UDP payload size of 1232 bytes (`?MAX_PACKET_SIZE`),
    which is the recommended maximum size for DNS over UDP to avoid IP fragmentation.
3. **Payload Size Adjustment**: When a client sends a DNS request with an OPT RR containing
    an invalid UDP payload size (either too small or too large), we automatically adjust it
    to the maximum allowed size (1232 bytes) rather than rejecting the request.

This design decision prioritizes graceful degradation by automatically adjusting
invalid payload sizes rather than rejecting requests, while simultaneously protecting
against potential DoS attacks through oversized packets.
""".

-include_lib("dns_erlang/include/dns.hrl").

-behaviour(erldns_pipeline).

-define(MIN_PACKET_SIZE, 512).
-define(MAX_PACKET_SIZE, 1232).

-export([call/2]).

-spec call(dns:message(), erldns_pipeline:opts()) -> dns:message().
call(#dns_message{} = Msg, #{transport := udp}) ->
    normalize_edns_max_payload_size(Msg);
call(Msg, _) ->
    Msg.

-spec normalize_edns_max_payload_size(dns:message()) -> dns:message().
normalize_edns_max_payload_size(Message) ->
    case Message#dns_message.additional of
        [#dns_optrr{udp_payload_size = Size} = OptRR | RestAdditional] ->
            case ?MIN_PACKET_SIZE =< Size andalso Size =< ?MAX_PACKET_SIZE of
                true ->
                    Message;
                false ->
                    OptRR1 = OptRR#dns_optrr{udp_payload_size = ?MAX_PACKET_SIZE},
                    Message#dns_message{additional = [OptRR1 | RestAdditional]}
            end;
        _ ->
            Message
    end.
