-module(erldns_handler).

-include("dns.hrl").
-include("erldns.hrl").

-export([handle/2]).

%% Handle the decoded message
handle({trailing_garbage, Message, _}, Host) ->
  handle(Message, Host);
handle(Message, Host) when is_record(Message, dns_message) ->
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
    {ok, CachedResponse} -> CachedResponse#dns_message{id=Message#dns_message.id};
    {error, _} -> handle_packet_cache_miss(Message, get_soas(Message), Host)
  end.

handle_packet_cache_miss(Message, [], _Host) -> Message#dns_message{aa = false, rc = ?DNS_RCODE_NXDOMAIN};
handle_packet_cache_miss(Message, _, Host) ->
  Message2 = Message#dns_message{ra = false},
  case application:get_env(erldns, catch_exceptions) of
    {ok, false} -> maybe_cache_packet(resolve(Message2, Host));
    _ ->
      try resolve(Message2, Host) of
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

resolve(Message, Host) ->
  % Step 1: Set the RA bit to false
  Message2 = Message#dns_message{ra = false},
  % Step 2: Search the available zones for the zone which is the nearest ancestor to QNAME
  [Question|_] = Message2#dns_message.questions,
  Records = erldns_pgsql:lookup_records(Question#dns_query.name),
  additional_processing(resolve(Message2, Question#dns_query.name, Question#dns_query.type, Records, Host), Host).

resolve(Message, Qname, Qtype, Records, Host) -> resolve(Message, Qname, Qtype, Records, Host, false, []).

resolve(Message, Qname, Qtype, Records, Host, Wildcard, CnameChain) ->
  % Step 3a: Exact match
  AllRecords = to_dns_rr(lists:map(fun(R) -> erldns_pgsql_responder:db_to_record(Qname, R) end, Records)),
  FilteredRecords = lists:filter(fun(R) -> R#db_rr.name =:= Qname end, Records),
  case FilteredRecords of
    [] -> best_match_resolution(Message, Qname, Qtype, Records, Host, Wildcard, CnameChain, best_match(Qname, AllRecords), AllRecords);
    MatchedRecords -> exact_match_resolution(Message, Qname, Qtype, Records, Host, Wildcard, CnameChain, MatchedRecords, AllRecords)
  end.

exact_match_resolution(Message, Qname, Qtype, Records, Host, Wildcard, CnameChain, MatchedRecords, AllRecords) ->
  lager:info("Exact matches found: ~p", [length(MatchedRecords)]),
  RRs = to_dns_rr(lists:map(fun(R) -> erldns_pgsql_responder:db_to_record(Qname, R) end, MatchedRecords)),
  AnyCnames = lists:any(match_type(?DNS_TYPE_CNAME), RRs),
  case AnyCnames of
    true ->
      lager:info("Found CNAME records in matches"),
      case Qtype of
        ?DNS_TYPE_CNAME ->
          TypeMatches = lists:filter(match_type(Qtype), RRs),
          Message#dns_message{aa = true, answers = Message#dns_message.answers ++ TypeMatches};
        _ ->
          lager:info("Found CNAME, but qtype is ~p", [Qtype]),
          RR = lists:last(lists:filter(match_type(?DNS_TYPE_CNAME), RRs)),
          case lists:member(RR, CnameChain) of
            true ->
              Message#dns_message{aa = true, rc = ?DNS_RCODE_SERVFAIL};
            false ->
              lager:info("Restarting query with CNAME name ~p", [RR#dns_rr.data#dns_rrdata_cname.dname]),
              resolve(Message#dns_message{aa = true, answers = Message#dns_message.answers ++ [RR]}, RR#dns_rr.data#dns_rrdata_cname.dname, Qtype, Records, Host, Wildcard, CnameChain ++ [RR])
          end
      end;
    false ->
      lager:info("No CNAME records found in matches"),
      % Step 3b: Referrals
      AnyReferrals = lists:any(match_type(?DNS_TYPE_NS), RRs),
      IsAuthority = lists:any(match_type(?DNS_TYPE_SOA), RRs),
      ExactTypeMatch = lists:any(match_type(Qtype), RRs),
      case ExactTypeMatch of
        true -> Message#dns_message{aa = true, rc = ?DNS_RCODE_NOERROR, answers = lists:filter(match_type(Qtype), RRs)};
        false ->
          case AnyReferrals of
            true ->
              lager:info("Found referrals"),
              case IsAuthority of
                true ->
                  lager:info("Found an SOA record"),
                  case Qtype of
                    ?DNS_TYPE_ANY -> Message#dns_message{aa = true, answers = RRs};
                    ?DNS_TYPE_NS -> Message#dns_message{aa = true, answers = lists:filter(match_type(?DNS_TYPE_NS), RRs)};
                    ?DNS_TYPE_SOA -> Message#dns_message{aa = true, answers = lists:filter(match_type(?DNS_TYPE_SOA), RRs)};
                    _ -> Message#dns_message{aa = true, rc = ?DNS_RCODE_NOERROR, authority = lists:filter(match_type(?DNS_TYPE_SOA), RRs)}
                  end;
                false ->
                  NSRecords = lists:filter(match_type(?DNS_TYPE_NS), RRs),
                  Message#dns_message{authority = Message#dns_message.authority ++ NSRecords}
              end;
            false ->
              lager:info("No referrals"),
              Authority = lists:filter(match_type(?DNS_TYPE_SOA), AllRecords),
              TypeMatches = case Qtype of
                ?DNS_TYPE_ANY -> RRs;
                _ -> lists:filter(match_type(Qtype), RRs)
              end,
              lager:info("Type matches: ~p", [TypeMatches]),
              case TypeMatches of
                [] ->
                  case CnameChain of
                    [] -> Message#dns_message{aa = true, authority = Authority};
                    _ -> rewrite_soa_ttl(Message#dns_message{aa = true, authority = Authority})
                  end;
                _ -> Message#dns_message{aa = true, answers = Message#dns_message.answers ++ TypeMatches}
              end
          end
      end
  end.

best_match_resolution(Message, Qname, Qtype, Records, Host, _Wildcard, CnameChain, BestMatchRecords, _AllRecords) ->
  lager:info("No exact match found, using ~p", [BestMatchRecords]),

  % Step 3b: Referrals
  AnyReferrals = lists:any(match_type(?DNS_TYPE_NS), BestMatchRecords),
  IsAuthority = lists:any(match_type(?DNS_TYPE_SOA), BestMatchRecords),
  case AnyReferrals of
    true ->
      lager:info("Referral found"),
      case IsAuthority of
        true ->
          Authority = lists:filter(match_type(?DNS_TYPE_SOA), BestMatchRecords),
          lager:info("Is authority: ~p", [Authority]),
          case CnameChain of
            [] -> rewrite_soa_ttl(Message#dns_message{aa = true, rc = ?DNS_RCODE_NXDOMAIN, authority = Authority});
            _ ->
              case Qtype of
                ?DNS_TYPE_ANY -> Message;
                _ -> rewrite_soa_ttl(Message#dns_message{authority = Authority})
              end
          end;
        false ->
          lager:info("Is not authority"),
          NSRecords = lists:filter(match_type(?DNS_TYPE_NS), BestMatchRecords),
          lager:info("Referral found: ~p", [NSRecords]),
          AuthorityRecords = Message#dns_message.authority ++ NSRecords,
          Message#dns_message{aa = false, authority = AuthorityRecords}
      end;
    false ->
      % Step 3c
      lager:info("No referrals found"),
      IsWildcard = lists:any(match_wildcard(), BestMatchRecords),
      AnyCnames =  lists:any(match_type(?DNS_TYPE_CNAME), BestMatchRecords),
      case IsWildcard of
        true ->
          lager:info("Matched records are wildcard."),
          case AnyCnames of
            true ->
              lager:info("Wildcard record is CNAME"),
              case Qtype of
                ?DNS_TYPE_CNAME ->
                  TypeMatchedRecords = case Qtype of
                    ?DNS_TYPE_ANY -> BestMatchRecords;
                    _ -> lists:filter(match_type(Qtype), BestMatchRecords)
                  end,
                  TypeMatches = lists:map(replace_name(Qname), TypeMatchedRecords),
                  Message#dns_message{aa = true, answers = Message#dns_message.answers ++ TypeMatches};
                _ ->
                  lager:info("Found CNAME, but qtype is ~p", [Qtype]),
                  RR = lists:last(lists:filter(match_type(?DNS_TYPE_CNAME), lists:map(replace_name(Qname), BestMatchRecords))),
                  case lists:member(RR, CnameChain) of
                    true ->
                      Message#dns_message{aa = true, rc = ?DNS_RCODE_SERVFAIL};
                    false ->
                      lager:info("Restarting resolve with ~p", [RR#dns_rr.data#dns_rrdata_cname.dname]),
                      resolve(Message#dns_message{aa = true, answers = Message#dns_message.answers ++ [RR]}, RR#dns_rr.data#dns_rrdata_cname.dname, Qtype, Records, Host, IsWildcard, CnameChain ++ [RR])
                  end
              end;
            false ->
              lager:info("Wildcard is not CNAME"),
              TypeMatchedRecords = case Qtype of
                ?DNS_TYPE_ANY -> BestMatchRecords;
                _ -> lists:filter(match_type(Qtype), BestMatchRecords)
              end,
              TypeMatches = lists:map(replace_name(Qname), TypeMatchedRecords),
              Message#dns_message{aa = true, answers = TypeMatches}
          end;
        false ->
          lager:info("Matched records are not wildcard."),
          [Question|_] = Message#dns_message.questions,
          case Qname =:= Question#dns_query.name of
            true -> rewrite_soa_ttl(Message#dns_message{rc = ?DNS_RCODE_NXDOMAIN});
            false ->
              {Authority, Additional} = erldns_records:root_hints(),
              Message#dns_message{authority=Authority, additional=Additional}
          end
      end
  end.

%% Find the best match records for the given Qname in the
%% given Record set. This will attempt to walk through the
%% domain hierarchy in the Qname looking for both exact and
%% wildcard matches.
best_match(Qname, Records) -> best_match(Qname, dns:dname_to_labels(Qname), Records).

best_match(_Qname, [], _Records) -> [];
best_match(Qname, [_|Rest], Records) ->
  WildcardName = dns:labels_to_dname([<<"*">>] ++ Rest),
  case lists:filter(match_name(WildcardName), Records) of
    [] ->
      case Rest of
        [] -> [];
        _ ->
          lager:info("Rest: ~p", [Rest]),
          Name = dns:labels_to_dname(Rest),
          case lists:filter(match_name(Name), Records) of
            [] -> best_match(Qname, Rest, Records);
            Matches -> Matches
          end
      end;
    Matches -> Matches
  end.

%% Various matching functions.
match_type(Type) -> fun(R) when is_record(R, dns_rr) -> R#dns_rr.type =:= Type end.
match_name(Name) -> fun(R) -> 
      case R of
        _ when is_record(R, dns_rr) -> R#dns_rr.name =:= Name;
        _ -> lager:error("match_name(~p)(~p)", [Name, R]), false
      end
  end.
match_wildcard() -> fun(R) when is_record(R, dns_rr) -> lists:any(fun(L) -> L =:= <<"*">> end, dns:dname_to_labels(R#dns_rr.name)) end.

%% Replacement functions.
replace_name(Name) -> fun(R) when is_record(R, dns_rr) -> R#dns_rr{name = Name} end.

%% Check all of the questions against all of the responders.
%% TODO: optimize to return first match
%% TODO: rescue from case where soa function is not defined.
get_soas(Message) ->
  to_dns_rr(lists:flatten(lists:map(fun(Q) -> [F([Q#dns_query.name], Message) || F <- soa_functions()] end, Message#dns_message.questions))).

%% Get metadata for the domain connected to the given query name.
get_metadata(Qname, Message) ->
  lists:merge([F(Qname, Message) || F <- metadata_functions()]).

%% Answers are returned from responders as #rr records. This function
%% converts those types of records to #dns_rr records.
to_dns_rr(Answers) -> lists:map(
    fun(A) ->
      case A of
        R when is_record(R, rr) -> R#rr.dns_rr;
        R when is_record(R, dns_rr) -> R
      end
    end, lists:flatten(Answers)).

%% Do additional processing
additional_processing(Message, Host) ->
  Names = lists:flatten(requires_additional_processing(Message#dns_message.answers ++ Message#dns_message.authority, [])),
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
rewrite_soa_ttl(Message) -> rewrite_soa_ttl(Message, Message#dns_message.authority, []).
rewrite_soa_ttl(Message, [], NewAuthority) -> Message#dns_message{authority = NewAuthority};
rewrite_soa_ttl(Message, [R|Rest], NewAuthority) ->
  Rdata = R#dns_rr.data,
  Record = case Rdata of
    Data when is_record(Data, dns_rrdata_soa) -> R#dns_rr{ttl = erlang:min(Data#dns_rrdata_soa.minimum, R#dns_rr.ttl)};
    _ -> R
  end,
  rewrite_soa_ttl(Message, Rest, NewAuthority ++ [Record]).

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

