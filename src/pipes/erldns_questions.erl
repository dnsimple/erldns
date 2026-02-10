-module(erldns_questions).
-moduledoc """
Remove all redundant questions from a DNS message,
and parses the first question into a list of labels.

## Telemetry events

### `[erldns, pipeline, questions]`

Emitted when the questions pipe trims multiple questions down to one
(only the first question is processed).

- **Measurements:** `#{count => non_neg_integer()}` — number of questions removed
- **Metadata:** `#{host => host(), questions => [dns:query()]}`
""".

-include_lib("dns_erlang/include/dns.hrl").

-behaviour(erldns_pipeline).

-export([call/2]).

-doc "`c:erldns_pipeline:call/2` callback.".
-spec call(dns:message(), erldns_pipeline:opts()) -> erldns_pipeline:return().
call(#dns_message{qc = 0} = Msg, _) ->
    {stop, Msg#dns_message{qr = true}};
call(#dns_message{qc = 1, questions = [#dns_query{name = Name, type = Type}]} = Msg, Opts) ->
    LName = dns_domain:to_lower(Name),
    LLabels = dns_domain:split(LName),
    Opts1 = Opts#{query_name := LName, query_labels := LLabels, query_type := Type},
    {Msg, Opts1};
call(#dns_message{questions = [#dns_query{} = Q1 | Rest]} = Msg, #{host := Host} = Opts) ->
    LName = dns_domain:to_lower(Q1#dns_query.name),
    LLabels = dns_domain:split(LName),
    Measurements = #{count => length(Rest)},
    Metadata = #{host => Host, questions => [Q1 | Rest]},
    telemetry:execute([erldns, pipeline, questions], Measurements, Metadata),
    Msg1 = Msg#dns_message{qc = 1, questions = [Q1]},
    Opts1 = Opts#{query_name := LName, query_labels := LLabels, query_type := Q1#dns_query.type},
    {Msg1, Opts1}.
