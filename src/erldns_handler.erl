-module(erldns_handler).

-include("dns.hrl").
-include("erldns.hrl").

-export([handle/2]).

%% Handle the decoded message
handle({trailing_garbage, Message, _}, Host) ->
  handle(Message, Host);
handle(Message, Host) when is_record(Message, dns_message) ->
  lager:debug("From host ~p received decoded message: ~p", [Host, Message]),
  case erldns_query_throttle:throttle(Message, Host) of
    {throttled, Host, ReqCount} ->
      lager:info("Throttled ANY query for ~p. (req count: ~p)", [Host, ReqCount]),
      Message#dns_message{rc = ?DNS_RCODE_REFUSED};
    _ ->
      lager:info("Questions: ~p", [Message#dns_message.questions]),
      NewMessage = handle_message(Message, Host),
      complete_response(erldns_axfr:optionally_append_soa(erldns_edns:handle(NewMessage)))
  end;
handle(BadMessage, Host) ->
  lager:error("Received a bad message: ~p from ~p", [BadMessage, Host]),
  BadMessage.

%% Handle the message by hitting the packet cache and either
%% using the cached packet or continuing with the lookup process.
handle_message(Message, Host) ->
  case erldns_packet_cache:get(Message#dns_message.questions) of
    {ok, CachedResponse} ->
      lager:debug("Packet cache hit"),
      %folsom_metrics:notify({packet_cache_hit, 1}),
      CachedResponse#dns_message{id=Message#dns_message.id};
    {error, _} -> 
      lager:debug("Packet cache miss"),
      %folsom_metrics:notify({packet_cache_miss, 1}),
      handle_packet_cache_miss(Message, get_soas(Message), Host)
  end.

handle_packet_cache_miss(Message, [], _Host) -> Message#dns_message{aa = false, rc = ?DNS_RCODE_NXDOMAIN};
handle_packet_cache_miss(Message, _, Host) ->
  Message2 = Message#dns_message{ra = false},
  case application:get_env(erldns, catch_exceptions) of
    {ok, false} -> maybe_cache_packet(answer_questions(Message2, Host));
    _ ->
      try answer_questions(Message2, Host) of
        Response -> maybe_cache_packet(Response)
      catch
        Exception:Reason ->
          lager:error("Error answering request: ~p (~p)", [Exception, Reason]),
          Message2#dns_message{aa = false, rc = ?DNS_RCODE_SERVFAIL}
      end
  end.

maybe_cache_packet(Message) ->
  case Message#dns_message.aa of
    true -> erldns_packet_cache:put(Message#dns_message.questions, Message);
    _ -> ok
  end,
  Message.

%% Check all of the questions against all of the responders.
%% TODO: optimize to return first match
%% TODO: rescue from case where soa function is not defined.
get_soas(Message) ->
  to_dns_rr(lists:flatten(lists:map(fun(Q) -> [F([Q#dns_query.name], Message) || F <- soa_functions()] end, Message#dns_message.questions))).

get_soas_by_name(Qname, Message) ->
  to_dns_rr(lists:flatten([F([Qname], Message) || F <- soa_functions()])).

%% Look for an exact match SOA
get_exact_soas(Qname, Message) -> 
  to_dns_rr(query_responders(Qname, ?DNS_TYPE_SOA_NUMBER, Message)).

%% Get metadata for the domain connected to the given query name.
get_metadata(Qname, Message) ->
  lists:merge([F(Qname, Message) || F <- metadata_functions()]).

%% Answer the questions and return an updated copy of the given
%% Response.
answer_questions(Message, Host) ->
  answer_questions(Message#dns_message.questions, Message, Host).
answer_questions([], Message, Host) ->
  additional_processing(Message, Host);
answer_questions([Q|Rest], Message, Host) ->
  [Qname, Qtype] = [Q#dns_query.name, Q#dns_query.type],
  Answers = answer_question(Qname, Qtype, Host, Message),
  case cname_not_alone(Q, Answers, Message) of
    true ->
      Message#dns_message{aa = true, answers = to_dns_rr(extract_cname(Answers, Qname, Qtype, Host, Message)), rc = ?DNS_RCODE_NOERROR, authority = get_soas(Message)};
    false ->
      NewAnswers = to_dns_rr(lists:flatten(resolve_cnames(Qtype, Answers, Host, Message))),
      case NewAnswers of
        [] -> try_delegation(Qname, Rest, get_exact_soas(Qname, Message), Message, Host);
        _ -> answer_questions(Rest, Message#dns_message{aa = true, answers = NewAnswers}, Host)
      end
  end.

%% Answers are returned from responders as #rr records. This function
%% converts those types of records to #dns_rr records.
to_dns_rr(Answers) -> lists:map(
    fun(A) ->
      case A of
        R when is_record(R, rr) -> R#rr.dns_rr;
        R when is_record(R, dns_rr) -> R
      end
    end, Answers).

% This logic is FUBAR'ed.
extract_cname(Answers, Qname, Qtype, Host, Message) -> 
  CnameRecords = lists:filter(fun(A) -> A#rr.dns_rr#dns_rr.type =:= ?DNS_TYPE_CNAME end, Answers), 
  ResolvedCnameAnyRecords = to_dns_rr(lists:flatten(resolve_any_cnames(CnameRecords, Host, Message))),
  case lists:any(fun(R) -> R#dns_rr.type =:= Qtype end, ResolvedCnameAnyRecords) of
    false ->
      case lists:any(fun(R) -> R#dns_rr.name =:= Qname end, ResolvedCnameAnyRecords) of
        true -> 
          lists:filter(fun(A) -> A#rr.wildcard =:= false end, CnameRecords);
        false ->
          []
      end;
    true ->
      lists:filter(fun(A) -> A#rr.wildcard =:= false end, CnameRecords)
  end.

cname_not_alone(Q, Answers, Message) ->
  case lists:any(fun(A) -> A#dns_rr.type =:= ?DNS_TYPE_CNAME end, to_dns_rr(Answers)) of
    true -> length(query_responders(Q#dns_query.name, ?DNS_TYPE_ANY, Message)) > 0;
    false -> false
  end.

%% Do additional processing
additional_processing(Message, Host) ->
  Names = lists:flatten(requires_additional_processing(Message#dns_message.answers, [])),
  case Names of
    [] -> Message;
    _ ->
      Records = lists:flatten(lists:map(
          fun(Qname) ->
              resolve_cnames(?DNS_TYPE_A, answer_question(Qname, ?DNS_TYPE_A, Host, Message), Host, Message)
          end, Names)),
      Additional = Message#dns_message.additional ++ Records,
      AdditionalCount = length(Additional),
      Message#dns_message{adc=AdditionalCount, additional=Additional}
  end.

%% Given a list of answers find the names that require additional processing.
requires_additional_processing([], RequiresAdditional) -> RequiresAdditional;
requires_additional_processing([Answer|Rest], RequiresAdditional) ->
  Names = case Answer#dns_rr.data of
    Data when is_record(Data, dns_rrdata_ns) -> [Data#dns_rrdata_ns.dname];
    Data when is_record(Data, dns_rrdata_mx) -> [Data#dns_rrdata_mx.exchange];
    _ -> []
  end,
  requires_additional_processing(Rest, RequiresAdditional ++ Names).

%% Try to delegate a Qname since we couldn't find any answers.
try_delegation(Qname, Questions, [], Message, Host) ->
  case answer_question(Qname, ?DNS_TYPE_NS_NUMBER, Host, Message) of
    [] -> 
      answer_questions(Questions, Message#dns_message{aa = true, rc = ?DNS_RCODE_NXDOMAIN, authority = rewrite_soa_ttl(get_soas_by_name(Qname, Message))}, Host);
    Answers -> 
      answer_questions(Questions, Message#dns_message{aa = false, authority = Answers}, Host)
  end;
try_delegation(Qname, Questions, _, Message, Host) ->
  answer_questions(Questions, Message#dns_message{aa = true, authority = get_soas_by_name(Qname, Message)}, Host).

%% Retreive all answers to the specific question.
answer_question(Qname, Qtype = ?DNS_TYPE_AXFR_NUMBER, Host, Message) ->
  lager:info("Answers AXFR question for host ~p", [Host]),
  case erldns_axfr:is_enabled(Host, get_metadata(Qname, Message)) of
    true -> query_responders(Qname, Qtype, Message);
    _ ->
      lager:info("AXFR not allowed."),
      []
  end;
answer_question(Qname, Qtype, _, Message) ->
  query_responders(Qname, Qtype, Message).

%% Get the answers for a query from the responders.
query_responders(Qname, Qtype, Message) ->
  query_responders(Qname, Qtype, Message, answer_functions()).
query_responders(_Qname, _Qtype, _Message, []) -> [];
query_responders(Qname, Qtype, Message, [F|AnswerFunctions]) ->
  case Answers = F(Qname, dns:type_name(Qtype), Message) of
    [] -> query_responders(Qname, Qtype, Message, AnswerFunctions);
    _ -> Answers
  end.

%% Update the message counts and set the QR flag to true.
complete_response(Message) ->
   Message#dns_message{
    anc = length(Message#dns_message.answers),
    auc = length(Message#dns_message.authority),
    adc = length(Message#dns_message.additional),
    qr = true
  }.

%% According to RFC 2308 the TTL for the SOA record in an NXDOMAIN response
%% must be set to the value of the minimum field in the SOA content.
rewrite_soa_ttl(Authority) -> rewrite_soa_ttl(Authority, []).
rewrite_soa_ttl([], NewAuthority) -> NewAuthority;
rewrite_soa_ttl([R|Rest], NewAuthority) ->
  Rdata = R#dns_rr.data,
  Record = case Rdata of
    Data when is_record(Data, dns_rrdata_soa) -> R#dns_rr{ttl = Data#dns_rrdata_soa.minimum};
    _ -> R
  end,
  rewrite_soa_ttl(Rest, NewAuthority ++ [Record]).

%% Build a list of answer functions based on the registered responders.
answer_functions() ->
  lists:map(fun(M) -> fun M:answer/3 end, get_responder_modules()).

%% Build a list of functions for looking up SOA records based on the
%% registered responders.
soa_functions() ->
  lists:map(fun(M) -> fun M:get_soa/2 end, get_responder_modules()).

%% Build a list of functions for getting metdata based on the registered
%% responders.
metadata_functions() ->
  lists:map(fun(M) -> fun M:get_metadata/2 end, get_responder_modules()).

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
resolve_cnames(Qtype, Records, Host, Message) ->
  case Qtype of
    ?DNS_TYPE_CNAME_NUMBER -> Records;
    ?DNS_TYPE_AXFR_NUMBER -> Records;
    ?DNS_TYPE_ANY_NUMBER -> Records;
    _ -> [resolve_cname(Qtype, Record, Host, Message) || Record <- to_dns_rr(Records)]
  end.

%% Restart the query.
resolve_cname(OriginalQtype, Record, Host, Message) ->
  lager:debug("~p:resolve_cname(~p, ~p, ~p)~n", [?MODULE, OriginalQtype, Record, Host]),
  case Record#dns_rr.type of
    ?DNS_TYPE_CNAME_NUMBER ->
      Qname = Record#dns_rr.data#dns_rrdata_cname.dname,
      answer_question(Qname, OriginalQtype, Host, Message) ++ [Record];
    _ ->
      Record
  end.

resolve_any_cnames(Records, Host, Message) ->
  [resolve_cname(?DNS_TYPE_ANY, Record, Host, Message) || Record <- to_dns_rr(Records)].
