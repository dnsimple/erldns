-module(erldns_handler).

-include("dns_records.hrl").

-define(AXFR_ENABLED, true).

-export([handle/2, build_response/2]).

%% Handle the decoded message
handle({trailing_garbage, DecodedMessage, _}, Host) ->
  handle(DecodedMessage, Host);
handle(DecodedMessage, Host) ->
  lager:debug("From host ~p received decoded message: ~p~n", [Host, DecodedMessage]),
  Questions = DecodedMessage#dns_message.questions,
  lager:info("Questions: ~p~n", [Questions]),
  Message = case erldns_packet_cache:get(Questions) of
    {ok, Answers} -> 
      lager:debug("Packet cache hit"), %% TODO: measure
      build_response(Answers, DecodedMessage);
    {error, _} -> 
      lager:debug("Packet cache miss"), %% TODO: measure
      case check_soa(Questions) of
        true ->
          Response = answer_questions(Questions, DecodedMessage),
          erldns_packet_cache:put(Questions, Response#dns_message.answers),
          Response;
        _ ->
          %% TODO: should this response be packet cached?
          nxdomain_response(DecodedMessage)
      end
  end,
  erldns_axfr:optionally_append_soa(erldns_edns:handle(Message)).

%% Check to see if we are authoritative for the domain.
check_soa(Questions) ->
  case check_soas(Questions) of
    [] -> false;
    _ -> true
  end.

%% Check all of the questions against all of the responders.
%% TODO: optimize to return first match
%% TODO: rescue from case where soa function is not defined.
check_soas(Questions) ->
  lists:flatten(lists:map(fun(Q) -> [F([Q#dns_query.name]) || F <- soa_functions()] end, Questions)).

%% Answer the questions and return an updated copy of the given
%% Response.
answer_questions([], Response) ->
  Response;
answer_questions([Q|Rest], Response) ->
  [Qname, Qtype] = [Q#dns_query.name, Q#dns_query.type],
  answer_questions(Rest, build_response(lists:flatten(resolve_cnames(Qtype, answer_question(Qname, Qtype))), Response)).

%% Retreive all answers to the specific question.
answer_question(Qname, Qtype = ?DNS_TYPE_AXFR_BSTR) ->
  case ?AXFR_ENABLED of
    true -> query_responders(Qname, Qtype);
    _ -> lager:info("AXFR not enabled."), []
  end;
answer_question(Qname, Qtype) ->
  query_responders(Qname, Qtype).

%% Get the answers for a query from the responders.
query_responders(Qname, Qtype) ->
  lists:flatten([F(Qname, dns:type_name(Qtype)) || F <- answer_functions()]).

% Return an NXDOMAIN response since we are not authoritative.
nxdomain_response(Message) ->
  Message#dns_message{anc = 0, qr = true, aa = false, rc = ?DNS_RCODE_NXDOMAIN, answers = []}.

%% Populate a response with the given answers
build_response(Answers, Response) ->
  NewResponse = Response#dns_message{anc = length(Answers), qr = true, aa = true, answers = Answers},
  lager:debug("Response: ~p~n", [NewResponse]),
  NewResponse.

%% Build a list of answer functions based on the registered responders.
answer_functions() ->
  lists:map(fun(M) -> fun M:answer/2 end, get_responder_modules()).

%% Build a list of functions for looking up SOA records based on the
%% registered responders.
soa_functions() ->
  lists:map(fun(M) -> fun M:get_soa/1 end, get_responder_modules()).

%% Find the responder module names from the app environment. Default 
%% to just the erldns_mysql_responder.
get_responder_modules() -> get_responder_modules(application:get_env(erldns, responders)).
get_responder_modules({ok, RM}) -> RM;
get_responder_modules(_) -> [erldns_mysql_responder].

%% According to RFC 1034:
%%
%% "CNAME RRs cause special action in DNS software.
%% When a name server fails to find a desired RR
%% in the resource set associated with the domain name,
%% it checks to see if the resource set consists
%% of a CNAME record with a matching class.  If so, the
%% name server includes the CNAME record in the
%% response and restarts the query at the domain name
%% specified in the data field of the CNAME record.
%% The one exception to this rule is that queries which
%% match the CNAME type are not restarted."
resolve_cnames(Qtype, Records) ->
  case Qtype of
    ?DNS_TYPE_CNAME_NUMBER -> Records;
    ?DNS_TYPE_AXFR_NUMBER -> Records;
    ?DNS_TYPE_ANY_NUMBER -> Records;
    _ -> [resolve_cname(Qtype, Record) || Record <- Records]
  end.

%% Restart the query.
resolve_cname(OriginalQtype, Record) ->
  case Record#dns_rr.type of
    ?DNS_TYPE_CNAME_NUMBER ->
      lager:debug("~p:resolve_cname(~p)~n", [?MODULE, Record]),
      Qname = Record#dns_rr.data#dns_rrdata_cname.dname,
      answer_question(Qname, OriginalQtype) ++ [Record];
    _ ->
      Record
  end.
