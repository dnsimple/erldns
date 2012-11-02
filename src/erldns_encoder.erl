-module(erldns_encoder).

-include("dns_records.hrl").

-export([encode_message/1]).

encode_message(Response) ->
  try dns:encode_message(Response) of
    M -> M
  catch
    Exception:Reason ->
      lager:error("Error encoding ~p (~p:~p)", [Response, Exception, Reason]),
      encode_message(build_error_response(Response))
  end.

%% Populate a response with a servfail error
build_error_response(Response) when is_record(Response, dns_message) ->
  build_error_response(Response, ?DNS_RCODE_SERVFAIL);
build_error_response({_, Response}) ->
  build_error_response(Response, ?DNS_RCODE_SERVFAIL).
build_error_response(Response, Rcode) ->
  Response#dns_message{anc = 0, qr = true, aa = true, rc = Rcode, answers=[]}.
