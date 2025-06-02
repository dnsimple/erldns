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

-module(erldns_encoder).
-moduledoc false.

-include_lib("kernel/include/logger.hrl").
-include_lib("dns_erlang/include/dns_records.hrl").

-export([encode_message/1, encode_message/2]).

-doc """
Encode the DNS message into its binary representation.
""".
-spec encode_message(dns:message()) -> dns:message_bin().
encode_message(Message) ->
    try dns:encode_message(Message) of
        M ->
            M
    catch
        Class:Reason:Stacktrace ->
            ?LOG_ERROR(#{
                what => encoding_message_failed,
                class => Class,
                reason => Reason,
                stacktrace => Stacktrace,
                message => Message
            }),
            encode_message(build_error_response(Message))
    end.

-doc """
Encode the DNS message into its binary representation.

Use the Opts argument to pass in encoding options.
""".
-spec encode_message(dns:message(), dns:encode_message_opts()) ->
    {false, dns:message_bin()}
    | {true, dns:message_bin(), dns:message()}
    | {false, dns:message_bin(), dns:tsig_mac()}
    | {true, dns:message_bin(), dns:tsig_mac(), dns:message()}.
encode_message(Message, Opts) ->
    try dns:encode_message(Message, Opts) of
        M ->
            M
    catch
        Class:Reason:Stacktrace ->
            ?LOG_ERROR(#{
                what => encoding_message_failed,
                class => Class,
                reason => Reason,
                stacktrace => Stacktrace,
                message => Message,
                opts => Opts
            }),
            {false, encode_message(build_error_response(Message))}
    end.

% Private functions

%% Populate a response with a servfail error
build_error_response(#dns_message{} = Message) ->
    build_error_response(Message, ?DNS_RCODE_SERVFAIL);
build_error_response({_, #dns_message{} = Message}) ->
    build_error_response(Message, ?DNS_RCODE_SERVFAIL).

build_error_response(Message, Rcode) ->
    Message#dns_message{
        anc = 0,
        auc = 0,
        adc = 0,
        qr = true,
        aa = true,
        rc = Rcode,
        answers = [],
        authority = [],
        additional = []
    }.
