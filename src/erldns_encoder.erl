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

%% @doc Safe response encoding, where exceptions will not result in a full
%% system crash.
-module(erldns_encoder).

-include_lib("dns_erlang/include/dns_records.hrl").

-export([encode_message/1, encode_message/2]).

%% @doc Encode the DNS message into its binary representation.
%%
%% Note that if the erldns catch_exceptions property is set in the
%% configuration, then this function should never throw an 
%% exception.
-spec encode_message(dns:message()) -> dns:message_bin().
encode_message(Response) ->
  case application:get_env(erldns, catch_exceptions) of
    {ok, false} -> dns:encode_message(Response);
    _ ->
      try dns:encode_message(Response) of
        M -> M
      catch
        Exception:Reason ->
          lager:error("Error encoding (response: ~p, exception: ~p, reason: ~p)", [Response, Exception, Reason]),
          encode_message(build_error_response(Response))
      end
  end.

%% @doc Encode the DNS message into its binary representation. Use the
%% Opts argument to pass in encoding options.
%%
%% Note that if the erldns catch_exceptions property is set in the
%% configuration, then this function should never throw an 
%% exception.
-spec encode_message(dns:message(), [dns:encode_message_opt()]) ->
  {false, dns:message_bin()} |
  {true, dns:message_bin(), dns:message()} |
  {false, dns:message_bin(), dns:tsig_mac()} |
  {true, dns:message_bin(), dns:tsig_mac(), dns:message()}.
encode_message(Response, Opts) ->
  case application:get_env(erldns, catch_exceptions) of
    {ok, false} -> dns:encode_message(Response, Opts);
    _ ->
      try dns:encode_message(Response, Opts) of
        M -> M
      catch
        Exception:Reason ->
          lager:error("Error encoding with truncation (response: ~p, exception: ~p, reason: ~p)", [Response, Exception, Reason]),
          {false, encode_message(build_error_response(Response))}
      end
  end.

% Private functions

%% Populate a response with a servfail error
build_error_response(Response) when is_record(Response, dns_message) ->
  build_error_response(Response, ?DNS_RCODE_SERVFAIL);
build_error_response({_, Response}) ->
  build_error_response(Response, ?DNS_RCODE_SERVFAIL).
build_error_response(Response, Rcode) ->
  Response#dns_message{anc = 0, auc = 0, adc = 0, qr = true, aa = true, rc = Rcode, answers=[], authority=[], additional=[]}.
