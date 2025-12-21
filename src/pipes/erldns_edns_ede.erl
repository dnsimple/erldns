-module(erldns_edns_ede).
-moduledoc """
Add Extended DNS Error (EDE) options to DNS responses.

This pipeline handler implements RFC 8914 Extended DNS Errors, which provides
additional error information in DNS responses through EDNS0 options. This helps
clients better understand why a query failed or why a particular response was returned.

## Configuration

The handler can be configured through application configuration:

```erlang
{erldns, [
    {packet_pipeline, [
        ...,
        erldns_edns_ede,
        ...
    ]},
    {edns_ede, #{
        enabled => true, %% Enable/disable EDE support (default: true)
        add_text => true %% Include EXTRA-TEXT in EDE (default: false)
    }
]}
```

## Behavior

This handler examines the DNS response and adds appropriate EDE options based on:

- Response code (SERVFAIL, REFUSED, FORMERR, etc.)
- DNSSEC validation failures
- Resolver errors stored in options

EDE codes are only added for error responses (SERVFAIL, REFUSED, FORMERR).
Valid negative responses like NXDOMAIN do not include EDE codes.

The handler automatically creates an OPT RR if one doesn't exist
and appends EDE options to existing OPT RR.

## References

- [RFC 8914](https://datatracker.ietf.org/doc/html/rfc8914) - Extended DNS Errors
""".

-include_lib("dns_erlang/include/dns.hrl").

-behaviour(erldns_pipeline).

-export([call/2, prepare/1]).

-doc "`c:erldns_pipeline:prepare/1` callback.".
-spec prepare(erldns_pipeline:opts()) -> erldns_pipeline:opts().
prepare(Opts) ->
    case enabled() of
        false -> disabled;
        true -> Opts#{?MODULE => add_text()}
    end.

-doc "`c:erldns_pipeline:call/2` callback.".
-spec call(dns:message(), erldns_pipeline:opts()) -> dns:message().
call(#dns_message{} = Msg, Opts) ->
    case determine_ede(Msg, Opts) of
        undefined ->
            Msg;
        Code ->
            Record = create_record(Code, Opts),
            add_ede_record(Msg, Record)
    end.

%% Determine which EDE codes to add based on message and options.
%%
%% Returns `undefined` if no EDE should be added (e.g., for NXDOMAIN which is
%% a valid negative response, not an error).
-spec determine_ede(dns:message(), erldns_pipeline:opts()) -> dns:uint16() | undefined.
%% REFUSED: Server is not authoritative for the queried domain
determine_ede(#dns_message{rc = ?DNS_RCODE_REFUSED}, #{resolved := false}) ->
    ?DNS_EDE_NOT_AUTHORITATIVE;
%% SERVFAIL: Generic server errors (exceptions, CNAME loops, encoding failures, etc.)
determine_ede(#dns_message{rc = ?DNS_RCODE_SERVFAIL}, _Opts) ->
    ?DNS_EDE_OTHER_ERROR;
%% NXDOMAIN: Valid negative response, not an error - don't add EDE
determine_ede(#dns_message{rc = ?DNS_RCODE_NXDOMAIN}, _Opts) ->
    undefined;
%% Other error response codes: Use OTHER_ERROR
determine_ede(#dns_message{rc = RC}, _Opts) when RC =/= ?DNS_RCODE_NOERROR ->
    ?DNS_EDE_OTHER_ERROR;
%% NOERROR: Successful response - don't add EDE
determine_ede(_Msg, _Opts) ->
    undefined.

create_record(Code, #{?MODULE := true}) ->
    case dns_names:ede_code_text(Code) of
        undefined ->
            #dns_opt_ede{info_code = Code};
        Text ->
            #dns_opt_ede{info_code = Code, extra_text = Text}
    end;
create_record(Code, _) ->
    #dns_opt_ede{info_code = Code}.

-spec add_ede_record(dns:message(), dns:optrr_elem()) -> dns:message().
add_ede_record(Message, Record) ->
    case Message#dns_message.additional of
        [#dns_optrr{} = OptRR | RestAdditional] ->
            %% Append to existing OPT RR
            UpdatedOptRR = OptRR#dns_optrr{data = [Record | OptRR#dns_optrr.data]},
            Message#dns_message{additional = [UpdatedOptRR | RestAdditional]};
        OtherAdditional ->
            %% Create new OPT RR with EDE
            NewOptRR = #dns_optrr{data = [Record]},
            Message#dns_message{additional = [NewOptRR | OtherAdditional]}
    end.

-spec enabled() -> boolean().
enabled() ->
    case application:get_env(erldns, edns_ede, #{}) of
        #{enabled := Bool} when is_boolean(Bool) ->
            Bool;
        _ ->
            true
    end.

-spec add_text() -> boolean().
add_text() ->
    case application:get_env(erldns, edns_ede, #{}) of
        #{add_text := Bool} when is_boolean(Bool) ->
            Bool;
        _ ->
            false
    end.
