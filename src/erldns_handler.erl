-module(erldns_handler).

-include("dns_records.hrl").

% Protected API
-export([handle/1]).

%% Handle the decoded message
handle(DecodedMessage) ->
  Questions = DecodedMessage#dns_message.questions,
  case erldns_packet_cache:get(Questions) of
    {ok, Answers} -> 
      lager:info("Packet cache hit"),
      build_response(Answers, DecodedMessage);
    {error, _} -> 
      lager:info("Packet cache miss"),
      Response = answer_questions(Questions, DecodedMessage),
      erldns_packet_cache:put(Questions, Response#dns_message.answers),
      Response
  end.

%% Answer the questions and return an updated copy of the given
%% Response.
answer_questions([], Response) ->
  Response;
answer_questions([Q|Rest], Response) ->
  lager:info("Question: ~p~n", [Q]),
  NewResponse = answer_question(Q, Response),
  answer_questions(Rest, NewResponse).

%% Add answers for a specific request to the given 
%% Response and return an updated copy of the Response.
answer_question(Q, Response) ->
  [Name, Type] = [Q#dns_query.name, Q#dns_query.type],

  ResponderModules = case application:get_env(erldns, responders) of
    {ok, RM} -> RM;
    _ -> [erldns_mysql_responder]
  end,

  Responders = lists:map(fun(M) -> fun M:answer/2 end, ResponderModules),

  Answers = lists:flatten(
    lists:map(
      fun(F) ->
          F(Name, dns:type_name(Type))
      end, Responders)),

  build_response(Answers, Response).

%% Populate a response with the given answers
build_response(Answers, Response) ->
  NewResponse = Response#dns_message{anc = length(Answers), qr=true, aa = true, answers = Answers},
  lager:info("Response: ~p~n", [NewResponse]),
  NewResponse.
