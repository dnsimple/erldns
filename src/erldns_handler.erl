-module(erldns_handler).

-include("dns_records.hrl").

-export([handle/1, build_response/2]).

%% Handle the decoded message
handle(DecodedMessage) ->
  Questions = DecodedMessage#dns_message.questions,
  Message = case erldns_packet_cache:get(Questions) of
    {ok, Answers} -> 
      lager:info("Packet cache hit"), %% TODO: measure
      build_response(Answers, DecodedMessage);
    {error, _} -> 
      lager:info("Packet cache miss"), %% TODO: measure
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
  lager:info("Question: ~p~n", [Q]),
  answer_questions(Rest, build_response(answer_question(Q#dns_query.name, Q#dns_query.type), Response)).

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
