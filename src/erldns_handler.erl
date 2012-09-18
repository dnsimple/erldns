-module(erldns_handler).

-include("dns_records.hrl").

-export([handle/1, build_response/2]).

%% Handle the decoded message
handle(DecodedMessage) ->
  lager:info("Decoded message: ~p~n", [DecodedMessage]),
  Questions = DecodedMessage#dns_message.questions,
  lager:info("Questions: ~p~n", [Questions]),
  Message = case erldns_packet_cache:get(Questions) of
    {ok, Answers} -> 
      lager:debug("Packet cache hit"), %% TODO: measure
      build_response(Answers, DecodedMessage);
    {error, _} -> 
      lager:debug("Packet cache miss"), %% TODO: measure
      %% TODO: ask all responders if we are authoritative?
      Response = answer_questions(Questions, DecodedMessage),
      erldns_packet_cache:put(Questions, Response#dns_message.answers),
      Response
  end,
  %% TODO: if there are no answers, check for an SOA. If no SOA then we are not authoritative
  erldns_edns:handle(Message).

%% Answer the questions and return an updated copy of the given
%% Response.
answer_questions([], Response) ->
  Response;
answer_questions([Q|Rest], Response) ->
  [Qname, Qtype] = [Q#dns_query.name, Q#dns_query.type],
  answer_questions(Rest, build_response(lists:flatten(resolve_cnames(Qtype, answer_question(Qname, Qtype))), Response)).

%% Retreive all answers to the specific question.
answer_question(Qname, Qtype) -> lists:flatten([F(Qname, dns:type_name(Qtype)) || F <- responders()]).

%% Populate a response with the given answers
build_response(Answers, Response) ->
  NewResponse = Response#dns_message{anc = length(Answers), qr = true, aa = true, answers = Answers},
  lager:debug("Response: ~p~n", [NewResponse]),
  NewResponse.

%% Build a list of responder functions that will be used to 
%% Lookup answers.
responders() -> lists:map(fun(M) -> fun M:answer/2 end, get_responder_modules()).

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
