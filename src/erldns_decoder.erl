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

%% @doc Safe response decoding, where exceptions will not result in a full
%% system crash
-module(erldns_decoder).

-include_lib("dns/include/dns_records.hrl").

-export([decode_message/1]).

%% @doc Decode the binary data into its Erlang representation.
%%
%% Note that if the erldns catch_exceptions property is set in the
%% configuration, then this function should never throw an 
%% exception.
-spec decode_message(dns:message_bin()) -> {dns:decode_error(), dns:message() | 'undefined', binary()} | dns:message().
decode_message(Bin) ->
  case application:get_env(erldns, catch_exceptions) of
    {ok, false} -> dns:decode_message(Bin);
    _ ->
      try dns:decode_message(Bin) of
        M -> M
      catch
        Exception:Reason ->
          lager:error("Error decoding message (data: ~p, exception: ~p, reason: ~p)", [Bin, Exception, Reason]),
          {formerr, Reason, Bin}
      end
  end.
