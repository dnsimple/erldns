-module(erldns_empty_verification).
-moduledoc """
Raise an event if the given message is empty or refused.

## Telemetry events

May emit the following telemetry events:

### `[erldns, pipeline, refused]`

Emitted when the empty verification pipe sees a resolved response with rcode REFUSED.

- **Measurements:** `#{count => 1}`
- **Metadata:** `#{}`

### `[erldns, pipeline, empty]`

Emitted when the empty verification pipe sees a resolved response with zero answer,
authority, and additional records.

- **Measurements:** `#{count => 1}`
- **Metadata:** `#{}`
""".

-include_lib("kernel/include/logger.hrl").
-include_lib("dns_erlang/include/dns.hrl").

-behaviour(erldns_pipeline).

-export([call/2]).

-doc "`c:erldns_pipeline:call/2` callback.".
-spec call(dns:message(), erldns_pipeline:opts()) -> dns:message().
call(#dns_message{rc = RC, anc = ANC, auc = AUC, adc = ADC} = Msg, #{resolved := true}) ->
    case {RC, ANC, AUC, ADC} of
        {?DNS_RCODE_REFUSED, _, _, _} ->
            telemetry:execute([erldns, pipeline, refused], #{count => 1}, #{}),
            Msg;
        {_, 0, 0, 0} ->
            ?LOG_INFO(#{what => empty_response, message => Msg}, #{domain => [erldns, pipeline]}),
            telemetry:execute([erldns, pipeline, empty], #{count => 1}, #{}),
            Msg;
        _ ->
            Msg
    end;
call(Msg, _) ->
    Msg.
