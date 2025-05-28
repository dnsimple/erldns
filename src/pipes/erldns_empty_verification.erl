-module(erldns_empty_verification).
-moduledoc """
Raise an event if the given message is empty or refused.
""".

-include_lib("kernel/include/logger.hrl").
-include_lib("dns_erlang/include/dns.hrl").

-behaviour(erldns_pipeline).

-export([call/2]).

-spec call(dns:message(), erldns_pipeline:opts()) ->
    dns:message() | {dns:message(), erldns_pipeline:opts()} | {stop, dns:message()}.
call(#dns_message{rc = RC, anc = ANC, auc = AUC, adc = ADC} = Msg, #{resolved := true}) ->
    case {RC, ANC, AUC, ADC} of
        {?DNS_RCODE_REFUSED, _, _, _} ->
            telemetry:execute([erldns, handler, refused], #{count => 1}, #{}),
            Msg;
        {_, 0, 0, 0} ->
            ?LOG_INFO(#{what => empty_response, message => Msg}),
            telemetry:execute([erldns, handler, empty], #{count => 1}, #{}),
            Msg;
        _ ->
            Msg
    end;
call(Msg, _) ->
    Msg.
