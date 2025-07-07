-module(erldns_questions).
-moduledoc """
Remove all redundant questions from a DNS message,
and parses the first question into a list of labels.

## Telemetry events

- `[erldns, pipeline, questions]` with `#{count => non_neg_integer()}`
where `count` is the number of questions removed.
""".

-include_lib("dns_erlang/include/dns.hrl").

-behaviour(erldns_pipeline).

-export([call/2]).

-doc "`c:erldns_pipeline:call/2` callback.".
-spec call(dns:message(), erldns_pipeline:opts()) -> erldns_pipeline:return().
call(#dns_message{questions = []} = Msg, _) ->
    {stop, Msg#dns_message{qr = true}};
call(#dns_message{questions = [#dns_query{} = Q1]} = Msg, Opts) ->
    Labels = dns:dname_to_lower_labels(Q1#dns_query.name),
    {Msg, Opts#{query_labels := Labels, query_type := Q1#dns_query.type}};
call(#dns_message{questions = [#dns_query{} = Q1, Q2 | Rest]} = Msg, #{host := Host} = Opts) ->
    Labels = dns:dname_to_lower_labels(Q1#dns_query.name),
    Measurements = #{count => 1 + length(Rest)},
    Metadata = #{host => Host, questions => [Q1, Q2 | Rest]},
    telemetry:execute([erldns, pipeline, questions], Measurements, Metadata),
    Msg1 = Msg#dns_message{qc = 1, questions = [Q1]},
    Opts1 = Opts#{query_labels := Labels, query_type := Q1#dns_query.type},
    {Msg1, Opts1}.
