-module(erldns_handler).

-include("dns.hrl").

-export([handle/2]).

%% Handle the decoded message
handle({trailing_garbage, DecodedMessage, _}, Host) ->
  handle(DecodedMessage, Host);
handle(DecodedMessage, Host) when is_record(DecodedMessage, dns_message) ->
  lager:debug("From host ~p received decoded message: ~p", [Host, DecodedMessage]),
  Questions = DecodedMessage#dns_message.questions,
  case erldns_query_throttle:throttle(DecodedMessage, Questions, Host) of
    {throttled, Host, ReqCount} ->
      lager:info("Throttled ANY query for ~p. (req count: ~p)", [Host, ReqCount]),
      DecodedMessage#dns_message{rc = ?DNS_RCODE_REFUSED};
    ThrottleResponse ->
      lager:debug("Throttle response: ~p", [ThrottleResponse]),
      Message = handle_message(DecodedMessage, Questions, Host),
      erldns_axfr:optionally_append_soa(erldns_edns:handle(Message))
  end;
handle(BadMessage, Host) ->
  lager:error("Received a bad message: ~p from ~p", [BadMessage, Host]),
  BadMessage.

%% Handle the message by hitting the packet cache and either
%% using the cached packet or continuing with the lookup process.
handle_message(DecodedMessage, Questions, Host) ->
  case erldns_packet_cache:get(Questions) of
    {ok, Answers, Authority, Additional} ->
      lager:debug("Packet cache hit"),
      %folsom_metrics:notify({packet_cache_hit, 1}),
      build_authoritative_response(Answers, Authority, Additional, DecodedMessage);
    {error, _} -> 
      lager:debug("Packet cache miss"),
      %folsom_metrics:notify({packet_cache_miss, 1}),
      handle_packet_cache_miss(DecodedMessage, Questions, get_soas(Questions), Host)
  end.

handle_packet_cache_miss(DecodedMessage, _Questions, [], _Host) ->
  %% TODO: should this response be packet cached?
  nxdomain_response(DecodedMessage);
handle_packet_cache_miss(DecodedMessage, Questions, _, Host) ->
  case application:get_env(erldns, catch_exceptions) of
    {ok, false} -> maybe_cache_packet(Questions, answer_questions(Questions, DecodedMessage, Host));
    _ ->
      try answer_questions(Questions, DecodedMessage, Host) of
        Response -> maybe_cache_packet(Questions, Response)
      catch
        Exception:Reason ->
          lager:error("Error answering request: ~p (~p)", [Exception, Reason]),
          error_response(DecodedMessage)
      end
  end.

maybe_cache_packet(Questions, Response) ->
  case Response#dns_message.aa of
    true -> erldns_packet_cache:put(Questions, Response#dns_message.answers, Response#dns_message.authority, Response#dns_message.additional);
    _ -> ok
  end,
  Response.

%% Check all of the questions against all of the responders.
%% TODO: optimize to return first match
%% TODO: rescue from case where soa function is not defined.
get_soas(Questions) ->
  lists:flatten(lists:map(fun(Q) -> [F([Q#dns_query.name]) || F <- soa_functions()] end, Questions)).

get_soas_by_name(Qname) ->
  lists:flatten([F([Qname]) || F <- soa_functions()]).

%% Look for an exact match SOA
get_exact_soas(Qname) -> query_responders(Qname, ?DNS_TYPE_SOA_NUMBER).

%% Get metadata for the domain connected to the given query name.
get_metadata(Qname) ->
  lists:merge([F(Qname) || F <- metadata_functions()]).

%% Answer the questions and return an updated copy of the given
%% Response.
answer_questions([], Response, Host) ->
  additional_processing(Response, Host);
answer_questions([Q|Rest], Response, Host) ->
  [Qname, Qtype] = [Q#dns_query.name, Q#dns_query.type],
  case lists:flatten(resolve_cnames(Qtype, answer_question(Qname, Qtype, Host), Host)) of
    [] -> try_delegation(Qname, Rest, get_exact_soas(Qname), Response, Host);
    Answers -> answer_questions(Rest, build_authoritative_response(Answers, [], [], Response), Host)
  end.

%% Do additional processing
additional_processing(Response, Host) ->
  Names = lists:flatten(requires_additional_processing(Response#dns_message.answers, [])),
  case Names of
    [] -> Response;
    _ ->
      Records = lists:flatten(lists:map(
          fun(Qname) ->
              resolve_cnames(?DNS_TYPE_A, answer_question(Qname, ?DNS_TYPE_A, Host), Host)
          end, Names)),
      Additional = Response#dns_message.additional ++ Records,
      AdditionalCount = length(Additional),
      Response#dns_message{adc=AdditionalCount, additional=Additional}
  end.

requires_additional_processing([], RequiresAdditional) -> RequiresAdditional;
requires_additional_processing([Answer|Rest], RequiresAdditional) ->
  Names = case Answer#dns_rr.data of
    Data when is_record(Data, dns_rrdata_ns) -> [Data#dns_rrdata_ns.dname];
    Data when is_record(Data, dns_rrdata_mx) -> [Data#dns_rrdata_mx.exchange];
    _ -> []
  end,
  requires_additional_processing(Rest, RequiresAdditional ++ Names).

%% Try to delegate a Qname since we couldn't find any answers.
try_delegation(Qname, Questions, [], Response, Host) ->
  case answer_question(Qname, ?DNS_TYPE_NS_NUMBER, Host) of
    [] -> answer_questions(Questions, build_authoritative_nxdomain_response([], get_soas_by_name(Qname), [], Response), Host);
    Answers -> answer_questions(Questions, build_delegated_response([], Answers, [], Response), Host)
  end;
try_delegation(Qname, Questions, _, Response, Host) ->
  answer_questions(Questions, build_authoritative_response([], get_soas_by_name(Qname), [], Response), Host).

%% Retreive all answers to the specific question.
answer_question(Qname, Qtype = ?DNS_TYPE_AXFR_NUMBER, Host) ->
  lager:info("Answers AXFR question for host ~p", [Host]),
  case erldns_axfr:is_enabled(Host, get_metadata(Qname)) of
    true -> query_responders(Qname, Qtype);
    _ ->
      lager:info("AXFR not allowed."),
      []
  end;
answer_question(Qname, Qtype, _) ->
  query_responders(Qname, Qtype).

%% Get the answers for a query from the responders.
query_responders(Qname, Qtype) ->
  query_responders(Qname, Qtype, answer_functions()).
query_responders(_Qname, _Qtype, []) -> [];
query_responders(Qname, Qtype, [F|AnswerFunctions]) ->
  case Answers = F(Qname, dns:type_name(Qtype)) of
    [] -> query_responders(Qname, Qtype, AnswerFunctions);
    _ -> Answers
  end.

% Return an NXDOMAIN response since we are not authoritative.
nxdomain_response(Message) ->
  Response = build_response([], [], [], Message),
  Response#dns_message{aa = false, rc = ?DNS_RCODE_NXDOMAIN}.

error_response(Message) ->
  Response = build_response([], [], [], Message),
  Response#dns_message{aa = false, rc = ?DNS_RCODE_SERVFAIL}.

build_delegated_response(Answers, Authority, Additional, Message) ->
  Response = build_response(Answers, Authority, Additional, Message),
  Response#dns_message{aa = false}.

build_authoritative_response(Answers, Authority, Additional, Message) ->
  Response = build_response(Answers, Authority, Additional, Message),
  Response#dns_message{aa = true}.

build_authoritative_nxdomain_response(Answers, Authority, Additional, Message) ->
  NewAuthority = rewrite_soa_ttl(Authority),
  Response = build_response(Answers, NewAuthority, Additional, Message),
  Response#dns_message{aa = true, rc = ?DNS_RCODE_NXDOMAIN}.

%% Populate a response with the given answers, authority and additional
%% sections.
build_response(Answers, Authority, Additional, Message) ->
  Message#dns_message{
    anc = length(Answers),
    auc = length(Authority),
    adc = length(Additional),
    qr = true,
    answers = Answers,
    authority = Authority,
    additional = Additional
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
  lists:map(fun(M) -> fun M:answer/2 end, get_responder_modules()).

%% Build a list of functions for looking up SOA records based on the
%% registered responders.
soa_functions() ->
  lists:map(fun(M) -> fun M:get_soa/1 end, get_responder_modules()).

%% Build a list of functions for getting metdata based on the registered
%% responders.
metadata_functions() ->
  lists:map(fun(M) -> fun M:get_metadata/1 end, get_responder_modules()).

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
resolve_cnames(Qtype, Records, Host) ->
  case Qtype of
    ?DNS_TYPE_CNAME_NUMBER -> Records;
    ?DNS_TYPE_AXFR_NUMBER -> Records;
    ?DNS_TYPE_ANY_NUMBER -> Records;
    _ -> [resolve_cname(Qtype, Record, Host) || Record <- Records]
  end.

%% Restart the query.
resolve_cname(OriginalQtype, Record, Host) ->
  lager:debug("~p:resolve_cname(~p, ~p, ~p)~n", [?MODULE, OriginalQtype, Record, Host]),
  case Record#dns_rr.type of
    ?DNS_TYPE_CNAME_NUMBER ->
      Qname = Record#dns_rr.data#dns_rrdata_cname.dname,
      answer_question(Qname, OriginalQtype, Host) ++ [Record];
    _ ->
      Record
  end.
