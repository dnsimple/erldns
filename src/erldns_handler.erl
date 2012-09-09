-module(erldns_handler).

-include("dns_records.hrl").

-export([handle/1, build_response/2]).

%% Handle the decoded message
handle(DecodedMessage) ->
  Questions = DecodedMessage#dns_message.questions,
  BaseMessage = case erldns_packet_cache:get(Questions) of
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
  %% if there are no answers, check for an SOA. If no SOA then we are not authoritative
  handle_additional_processing(BaseMessage).

%% Handle EDNS processing (includes DNSSEC?)
%% This is all experimental and doesn't do anything useful yet
handle_additional_processing(Message) ->
  handle_opts(Message, Message#dns_message.additional).

handle_opts(Message, []) ->
  Message;
handle_opts(Message, [Opt|Rest]) ->
  NewMessage = case Opt#dns_optrr.dnssec of
    true -> handle_dnssec(Message);
    false -> Message
  end,
  handle_opts(NewMessage, Rest).

handle_dnssec(Message) ->
  lager:info("Client wants DNSSEC"),
  Message.

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
  %% Query each of the responders that is registered
  %% to build the full answer set.
  Answers = lists:flatten([F(Name, dns:type_name(Type)) || F <- responders()]),
  build_response(Answers, Response).

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
