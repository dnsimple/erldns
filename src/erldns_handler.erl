-module(erldns_handler).

-include("dns.hrl").
-include("erldns.hrl").

-export([handle/2]).

% Internal API
-export([resolve/3]).

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

handle_packet_cache_miss(Message, [], _Host) ->
  {Authority, Additional} = erldns_records:root_hints(),
  Message#dns_message{aa = false, rc = ?DNS_RCODE_NOERROR, authority = Authority, additional = Additional};
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

find_zone(Qname) ->
  erldns_pgsql:lookup_records(normalize_name(Qname)).

measure(Name, FunctionName, Args) when is_list(Args) ->
  {T, R} = timer:tc(?MODULE, FunctionName, Args),
  erldns_metrics:insert(Name, T),
  lager:info("~p took ~p ms", [FunctionName, T / 1000]),
  R;
measure(Name, FunctionName, Arg) -> measure(Name, FunctionName, [Arg]).

%% Resolve the first question inside the given message.
resolve(Message, Host) ->
  case Message#dns_message.questions of
    [] -> Message;
    [Question] -> measure(Question#dns_query.name, resolve, [Message, Question, Host]);
    [Question|_] -> measure(Question#dns_query.name, resolve, [Message, Question, Host])
  end.

resolve(Message, Question, Host) ->
  % Step 1: Set the RA bit to false
  resolve(Message#dns_message{ra = false}, Question#dns_query.name, Question#dns_query.type, Host).

resolve(Message, Qname, Qtype, Host) ->
  % Step 2: Search the available zones for the zone which is the nearest ancestor to QNAME
  Records = find_zone(Qname),
  lager:info("Zone has ~p records", [length(Records)]),
  additional_processing(
    rewrite_soa_ttl(
      resolve(Message, Qname, Qtype, Records, Host)
    ), Host
  ).

resolve(Message, Qname, Qtype, Records, Host) -> resolve(Message, Qname, Qtype, Records, Host, false, []).

resolve(Message, Qname, Qtype, Records, Host, Wildcard, CnameChain) ->
  % Step 3a: Exact match
  AllRecords = lists:usort(lists:flatten(lists:map(fun(R) -> erldns_pgsql_responder:db_to_record(Qname, R) end, Records))),
  FilteredRecords = lists:filter(match_name(Qname), AllRecords),
  case FilteredRecords of
    [] -> best_match_resolution(Message, Qname, Qtype, Host, Wildcard, CnameChain, best_match(Qname, AllRecords), AllRecords);
    MatchedRecords -> exact_match_resolution(Message, Qname, Qtype, Host, Wildcard, CnameChain, MatchedRecords, AllRecords)
  end.

exact_match_resolution(Message, _Qname, Qtype, Host, Wildcard, CnameChain, MatchedRecords, AllRecords) ->
  lager:debug("Exact matches found: ~p", [length(MatchedRecords)]),
  RRs = MatchedRecords,
  AnyCnames = lists:any(match_type(?DNS_TYPE_CNAME), RRs),
  case AnyCnames of
    true ->
      lager:debug("Found CNAME records in matches"),
      case Qtype of
        ?DNS_TYPE_CNAME ->
          TypeMatches = lists:filter(match_type(Qtype), RRs),
          Message#dns_message{aa = true, answers = Message#dns_message.answers ++ TypeMatches};
        _ ->
          lager:debug("Found CNAME, but qtype is ~p", [Qtype]),
          RR = lists:last(lists:filter(match_type(?DNS_TYPE_CNAME), RRs)),
          case lists:member(RR, CnameChain) of
            true -> Message#dns_message{aa = true, rc = ?DNS_RCODE_SERVFAIL};
            false ->
              Name = RR#dns_rr.data#dns_rrdata_cname.dname,
              lager:debug("Restarting query with CNAME name ~p", [Name]),
              resolve(Message#dns_message{aa = true, answers = Message#dns_message.answers ++ [RR]}, Name, Qtype, find_zone(Name), Host, Wildcard, CnameChain ++ [RR])
          end
      end;
    false ->
      lager:debug("No CNAME records found in matches"),
      % Step 3b: Referrals
      AnyReferrals = lists:any(match_type(?DNS_TYPE_NS), RRs),
      IsAuthority = lists:any(match_type(?DNS_TYPE_SOA), RRs),
      ExactTypeMatch = lists:any(match_type(Qtype), RRs),
      case ExactTypeMatch of
        true ->
          lager:debug("Found exact type match"),
          Answers = lists:filter(match_type(Qtype), RRs),
          Answer = lists:last(Answers),
          case Qtype of
            ?DNS_TYPE_NS ->
              DelegatedName = Answer#dns_rr.name,
              lager:debug("Type was NS so we're looking to see if it's a delegation: ~p", [DelegatedName]),
              IsAuthority = lists:any(match_type(?DNS_TYPE_SOA), RRs),
              case IsAuthority of
                false ->
                  lager:debug("Restarting query with delegated name ~p", [DelegatedName]),
                  resolve(Message, DelegatedName, ?DNS_TYPE_A, find_zone(DelegatedName), Host, Wildcard, CnameChain);
                true ->
                  lager:debug("Authoritative for record, returning answers"),
                  Message#dns_message{aa = true, rc = ?DNS_RCODE_NOERROR, answers = Message#dns_message.answers ++ Answers}
              end;
            _ ->
              NSRecords = delegation_records(Answer#dns_rr.name, AllRecords),
              IsGlueRecord = length(NSRecords) > 0,
              case IsGlueRecord of
                true ->
                  NSRecord = lists:last(NSRecords),
                  DelegatedName = NSRecord#dns_rr.name,
                  lager:debug("Restarting query with delegated name ~p", [DelegatedName]),
                  resolve(Message, DelegatedName, Qtype, find_zone(DelegatedName), Host, Wildcard, CnameChain);
                false ->
                  lager:debug("Returning authoritative answer with ~p appended answers", [length(Answers)]),
                  Message#dns_message{aa = true, rc = ?DNS_RCODE_NOERROR, answers = Message#dns_message.answers ++ Answers}
              end
          end;
        false ->
          case AnyReferrals of
            true ->
              lager:debug("Found referrals"),
              case IsAuthority of
                true ->
                  lager:debug("Found an SOA record"),
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
              lager:debug("No referrals"),
              Authority = lists:filter(match_type(?DNS_TYPE_SOA), AllRecords),
              TypeMatches = case Qtype of
                ?DNS_TYPE_ANY -> RRs;
                _ -> lists:filter(match_type(Qtype), RRs)
              end,
              lager:debug("Type matches: ~p", [TypeMatches]),
              case TypeMatches of
                [] -> Message#dns_message{aa = true, authority = Authority};
                _ -> Message#dns_message{aa = true, answers = Message#dns_message.answers ++ TypeMatches}
              end
          end
      end
  end.

best_match_resolution(Message, Qname, Qtype, Host, _Wildcard, CnameChain, BestMatchRecords, AllRecords) ->
  lager:debug("No exact match found, using ~p", [BestMatchRecords]),

  % Step 3b: Referrals
  AnyReferrals = lists:any(match_type(?DNS_TYPE_NS), BestMatchRecords), 
  case AnyReferrals of
    true ->
      lager:debug("Referral found"),
      Authority = lists:filter(match_type(?DNS_TYPE_SOA), BestMatchRecords),
      IsAuthority = length(Authority) > 0,
      case IsAuthority of
        true ->
          lager:debug("Is authority: ~p", [Authority]),
          case CnameChain of
            [] -> Message#dns_message{aa = true, rc = ?DNS_RCODE_NXDOMAIN, authority = Authority};
            _ ->
              case Qtype of
                ?DNS_TYPE_ANY -> Message;
                _ -> Message#dns_message{authority = Authority}
              end
          end;
        false ->
          lager:debug("Is not authority"),
          NSRecords = lists:filter(match_type(?DNS_TYPE_NS), BestMatchRecords),
          Message#dns_message{aa = false, authority = Message#dns_message.authority ++ NSRecords}
      end;
    false ->
      % Step 3c
      lager:debug("No referrals found"),
      IsWildcard = lists:any(match_wildcard(), BestMatchRecords), 
      case IsWildcard of
        true ->
          lager:debug("Matched records are wildcard."),
          CnameMatches =  lists:filter(match_type(?DNS_TYPE_CNAME), BestMatchRecords),
          AnyCnames = length(CnameMatches) > 0,
          case AnyCnames of
            true ->
              lager:debug("Wildcard record is CNAME"),
              case Qtype of
                ?DNS_TYPE_CNAME ->
                  TypeMatchedRecords = case Qtype of
                    ?DNS_TYPE_ANY -> BestMatchRecords;
                    _ -> lists:filter(match_type(Qtype), BestMatchRecords)
                  end,
                  TypeMatches = lists:map(replace_name(Qname), TypeMatchedRecords),
                  Message#dns_message{aa = true, answers = Message#dns_message.answers ++ TypeMatches};
                _ ->
                  lager:debug("Found CNAME, but qtype is ~p", [Qtype]),
                  RR = lists:last(lists:filter(match_type(?DNS_TYPE_CNAME), lists:map(replace_name(Qname), BestMatchRecords))),
                  case lists:member(RR, CnameChain) of
                    true ->
                      Message#dns_message{aa = true, rc = ?DNS_RCODE_SERVFAIL};
                    false ->
                      Name = RR#dns_rr.data#dns_rrdata_cname.dname,
                      lager:debug("Restarting resolve with ~p", [Name]),
                      resolve(Message#dns_message{aa = true, answers = Message#dns_message.answers ++ [RR]}, Name, Qtype, find_zone(Name), Host, IsWildcard, CnameChain ++ [RR])
                  end
              end;
            false ->
              lager:debug("Wildcard is not CNAME"),
              TypeMatchedRecords = case Qtype of
                ?DNS_TYPE_ANY -> BestMatchRecords;
                _ -> lists:filter(match_type(Qtype), BestMatchRecords)
              end,
              TypeMatches = lists:map(replace_name(Qname), TypeMatchedRecords),
              case length(TypeMatches) of
                0 ->
                  Authority = lists:filter(match_type(?DNS_TYPE_SOA), AllRecords),
                  Message#dns_message{aa = true, authority=Authority};
                _ ->
                  Message#dns_message{aa = true, answers = Message#dns_message.answers ++ TypeMatches}
              end
          end;
        false ->
          lager:debug("Matched records are not wildcard."),
          [Question|_] = Message#dns_message.questions,
          case Qname =:= Question#dns_query.name of
            true ->
              Authority = lists:filter(match_type(?DNS_TYPE_SOA), AllRecords),
              Message#dns_message{rc = ?DNS_RCODE_NXDOMAIN, authority = Authority, aa = true};
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
match_name(Name) -> fun(R) when is_record(R, dns_rr) -> R#dns_rr.name =:= normalize_name(Name) end.
match_wildcard() -> fun(R) when is_record(R, dns_rr) -> lists:any(fun(L) -> L =:= <<"*">> end, dns:dname_to_labels(R#dns_rr.name)) end.
match_glue(Name) -> fun(R) when is_record(R, dns_rr) -> R#dns_rr.data =:= #dns_rrdata_ns{dname=Name} end.

%% Replacement functions.
replace_name(Name) -> fun(R) when is_record(R, dns_rr) -> R#dns_rr{name = Name} end.

%% Find all delegation records for the given Name in the provided
%% Records. This function may return an empty list, which means
%% the record is not a glue record.
delegation_records(Name, Records) -> lists:filter(fun(R) -> apply(match_type(?DNS_TYPE_NS), [R]) and apply(match_glue(Name), [R]) end, Records).

normalize_name(Name) when is_list(Name) -> string:to_lower(Name);
normalize_name(Name) when is_binary(Name) -> list_to_binary(string:to_lower(binary_to_list(Name))).

%% Check all of the questions against all of the responders.
%% TODO: optimize to return first match
%% TODO: rescue from case where soa function is not defined.
get_soas(Message) ->
  lists:flatten(lists:map(fun(Q) -> [F([normalize_name(Q#dns_query.name)], Message) || F <- soa_functions()] end, Message#dns_message.questions)).

%% Get metadata for the domain connected to the given query name.
get_metadata(Qname, Message) ->
  lists:merge([F(Qname, Message) || F <- metadata_functions()]).

%% Do additional processing
additional_processing(Message, Host) ->
  Names = lists:flatten(requires_additional_processing(Message#dns_message.answers ++ Message#dns_message.authority, [])),
  case Names of
    [] -> Message;
    _ ->
      lager:debug("Doing additional processing on ~p", [Names]),
      Records = lists:flatten(lists:map(
          fun(Qname) ->
              answer_question(Qname, ?DNS_TYPE_A, Host, Message)
          end, Names)),
      case Records of
        [] -> Message;
        _ ->
          lager:debug("Additional processing, found ~p records", [length(Records)]),
          Additional = Message#dns_message.additional ++ Records,
          AdditionalCount = length(Additional),
          Message#dns_message{adc=AdditionalCount, additional=Additional}
      end
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
