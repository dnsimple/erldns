-module(erldns_edns).
-moduledoc """
Separate the query's EDNS (RFC 6891) from the response's.

Put this pipe first in the pipeline; `m:erldns_resolver` requires it.

The pipeline turns the query into the response, so the OPT RR in the query's additional section is
what the response would send back. This pipe makes it the response's:

- The query's options move to the `query_edns_options` pipeline option, a map from option code to
  option (`t:query_edns_options/0`). If a code repeats, the first option is kept. The OPT RR keeps
  none: a server must ignore options it doesn't understand (RFC 6891 §6.1.2), and sending one back
  would claim support for it. A response only carries the options pipes add with `add_option/2`.
- The extended RCODE is reset to 0.
- The DO bit is kept, as it must be copied to the response (RFC 3225 §3), and so is the version,
  which dns_erlang answers with BADVERS when it doesn't support it.
- Over UDP, the payload size is capped, see below.

A query without an OPT RR gets none back (RFC 6891 §7). Any other record the query carries in its
additional section is dropped: the response's additional records are its own.

## EDNS extensions

An EDNS option is handled by a pipe of its own, which lists `erldns_edns` as a prerequisite, reads
the query's option from `query_edns_options` and adds the response's with `add_option/2`.

A pipe that adds an option depending on the query must run before the first
`m:erldns_packet_cache`, which looks answers up by the response's OPT RR as it is at that point.

## UDP payload size

DNS over UDP was limited to 512 bytes per message until EDNS let clients advertise a larger UDP
payload size in the OPT RR. Over UDP, a size below 512 bytes or above 1232 bytes is set to 1232,
the size recommended to avoid IP fragmentation, instead of rejecting the query. The size is the
limit at which the response is truncated.
""".

-include_lib("dns_erlang/include/dns.hrl").

-behaviour(erldns_pipeline).

-define(MIN_PACKET_SIZE, 512).
-define(MAX_PACKET_SIZE, 1232).

-export([prepare/1, call/2]).
-export([add_option/2, dnssec_ok/1]).
-export([get_opts/1, get_ede_errors/1]).

-doc "The query's EDNS options, by option code.".
-type query_edns_options() :: #{dns:eoptcode() => dns:optrr_elem()}.
-export_type([query_edns_options/0]).

-doc "`c:erldns_pipeline:prepare/1` callback.".
-spec prepare(erldns_pipeline:opts()) -> erldns_pipeline:opts().
prepare(Opts) ->
    Opts#{query_edns_options => #{}}.

-doc "`c:erldns_pipeline:call/2` callback.".
-spec call(dns:message(), erldns_pipeline:opts()) -> erldns_pipeline:return().
call(#dns_message{additional = []} = Msg, _) ->
    Msg;
call(#dns_message{additional = Additional} = Msg, #{transport := Transport} = Opts) ->
    case lists:keyfind(dns_optrr, 1, Additional) of
        false ->
            Msg#dns_message{adc = 0, additional = []};
        #dns_optrr{data = []} = OptRR ->
            with_optrr(Msg, OptRR, response_optrr(OptRR, Transport));
        #dns_optrr{data = Options} = OptRR ->
            Msg1 = with_optrr(Msg, OptRR, response_optrr(OptRR, Transport)),
            {Msg1, Opts#{query_edns_options => query_edns_options(Options)}}
    end.

-doc """
Add an option to the response's OPT RR.

Does nothing when the message has no OPT RR: a query without one gets none back (RFC 6891 §7).
""".
-spec add_option(dns:message(), dns:optrr_elem()) -> dns:message().
add_option(#dns_message{additional = Additional} = Msg, Option) ->
    case lists:keyfind(dns_optrr, 1, Additional) of
        #dns_optrr{data = Data} = OptRR ->
            OptRR1 = OptRR#dns_optrr{data = [Option | Data]},
            Msg#dns_message{additional = lists:keyreplace(dns_optrr, 1, Additional, OptRR1)};
        false ->
            Msg
    end.

-doc "Whether the message's OPT RR sets the DO bit (RFC 3225).".
-spec dnssec_ok(dns:message()) -> boolean().
dnssec_ok(#dns_message{additional = Additional}) ->
    case lists:keyfind(dns_optrr, 1, Additional) of
        #dns_optrr{dnssec = DnssecOk} -> DnssecOk;
        false -> false
    end.

%% Get a property list of EDNS0 options.
%%
%% Supported options are:
%%
%% * {dnssec, true}
-doc false.
-spec get_opts(dns:message()) -> [proplists:property()].
get_opts(Message) ->
    get_opts(Message#dns_message.additional, []).

-spec get_opts([dns:rr() | dns:optrr()], [proplists:property()]) -> [proplists:property()].
get_opts([#dns_optrr{dnssec = true} | Rest], Opts) ->
    get_opts(Rest, [{dnssec, true} | Opts]);
get_opts([_RR | Rest], Opts) ->
    get_opts(Rest, Opts);
get_opts([], Opts) ->
    lists:reverse(Opts).

%% Extract Extended DNS Errors from a message.
%%
%% Returns a list of {InfoCode, ExtraText} tuples for all EDE options
%% found in the message's OPT RR.
-doc false.
-spec get_ede_errors(dns:message()) -> [{non_neg_integer(), binary()}].
get_ede_errors(Message) ->
    get_ede_errors(Message#dns_message.additional, []).

-spec get_ede_errors([dns:rr() | dns:optrr()], [{non_neg_integer(), binary()}]) ->
    [{non_neg_integer(), binary()}].
get_ede_errors([#dns_optrr{data = Data} | Rest], Acc) ->
    EDEList = [
        {InfoCode, ExtraText}
     || #dns_opt_ede{info_code = InfoCode, extra_text = ExtraText} <- Data
    ],
    get_ede_errors(Rest, EDEList ++ Acc);
get_ede_errors([_RR | Rest], Acc) ->
    get_ede_errors(Rest, Acc);
get_ede_errors([], Acc) ->
    lists:reverse(Acc).

-spec response_optrr(dns:optrr(), erldns_pipeline:transport()) -> dns:optrr().
response_optrr(#dns_optrr{udp_payload_size = Size} = OptRR, udp) when
    Size < ?MIN_PACKET_SIZE; ?MAX_PACKET_SIZE < Size
->
    OptRR#dns_optrr{
        udp_payload_size = ?MAX_PACKET_SIZE, ext_rcode = ?DNS_ERCODE_NOERROR, data = []
    };
response_optrr(#dns_optrr{ext_rcode = ?DNS_ERCODE_NOERROR, data = []} = OptRR, _) ->
    OptRR;
response_optrr(OptRR, _) ->
    OptRR#dns_optrr{ext_rcode = ?DNS_ERCODE_NOERROR, data = []}.

%% The query's OPT RR becomes the only additional record. The header count is set here too, as
%% pipes that stop the pipeline early skip erldns_section_counter.
-spec with_optrr(dns:message(), dns:optrr(), dns:optrr()) -> dns:message().
with_optrr(#dns_message{adc = 1, additional = [OptRR]} = Msg, OptRR, OptRR) ->
    Msg;
with_optrr(Msg, _, OptRR) ->
    Msg#dns_message{adc = 1, additional = [OptRR]}.

%% Folding from the right lets the first option of each code overwrite later ones.
-spec query_edns_options([dns:optrr_elem()]) -> query_edns_options().
query_edns_options(Options) ->
    lists:foldr(fun(Option, Acc) -> Acc#{code(Option) => Option} end, #{}, Options).

-spec code(dns:optrr_elem()) -> dns:eoptcode().
code(#dns_opt_llq{}) -> ?DNS_EOPTCODE_LLQ;
code(#dns_opt_ul{}) -> ?DNS_EOPTCODE_UL;
code(#dns_opt_nsid{}) -> ?DNS_EOPTCODE_NSID;
code(#dns_opt_owner{}) -> ?DNS_EOPTCODE_OWNER;
code(#dns_opt_ecs{}) -> ?DNS_EOPTCODE_ECS;
code(#dns_opt_cookie{}) -> ?DNS_EOPTCODE_COOKIE;
code(#dns_opt_ede{}) -> ?DNS_EOPTCODE_EDE;
code(#dns_opt_unknown{id = Code}) -> Code.
