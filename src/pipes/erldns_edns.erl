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
- The DO bit is kept, as it must be copied to the response (RFC 3225 §3).
- A query with an EDNS version above 0 gets BADVERS, with no answer and no options, and the
  pipeline stops there (RFC 6891 §6.1.3).
- Over UDP, the payload size is capped, see below.

A query without an OPT RR gets none back (RFC 6891 §7). Any other record the query carries in its
additional section is dropped: the response's additional records are its own.

## EDNS extensions

An EDNS option is handled by a pipe of its own, which lists `erldns_edns` as a prerequisite, reads
the query's option from `query_edns_options` and adds the response's with `add_option/2`.

- `m:erldns_edns_ede` adds Extended DNS Errors (RFC 8914) to error responses.

A pipe that adds an option depending on the query must run before the first
`m:erldns_packet_cache`, which looks answers up by the response's OPT RR as it is at that point.
Listing `{optional, erldns_packet_cache}` among its dependents makes the pipeline check that.

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
-export([update_options/2, add_option/2, dnssec_ok/1]).
-export([get_opts/1, get_ede_errors/1]).

-doc """
The query's EDNS options, by option code.

An option that dns_erlang decodes into a record this module doesn't know yet is kept under the
record's name.
""".
-type query_edns_options() :: #{dns:eoptcode() | atom() => dns:optrr_elem()}.
-export_type([query_edns_options/0]).

-doc "`c:erldns_pipeline:prepare/1` callback.".
-spec prepare(erldns_pipeline:opts()) -> erldns_pipeline:opts().
prepare(Opts) ->
    Opts#{query_edns_options => #{}}.

-doc "`c:erldns_pipeline:call/2` callback.".
-spec call(dns:message(), erldns_pipeline:opts()) -> erldns_pipeline:return().
call(#dns_message{additional = []} = Msg, _) ->
    Msg;
call(#dns_message{additional = [#dns_optrr{} = OptRR]} = Msg, Opts) ->
    handle_optrr(Msg, OptRR, Opts);
call(#dns_message{additional = Additional} = Msg, Opts) ->
    case lists:keyfind(dns_optrr, 1, Additional) of
        false -> Msg#dns_message{adc = 0, additional = []};
        OptRR -> handle_optrr(Msg, OptRR, Opts)
    end.

-doc """
Apply `Fun` to the options of the response's OPT RR.

Does nothing when the message has no OPT RR: a query without one gets none back (RFC 6891 §7).
""".
-spec update_options(dns:message(), fun(([dns:optrr_elem()]) -> [dns:optrr_elem()])) ->
    dns:message().
update_options(#dns_message{additional = Additional} = Msg, Fun) ->
    case lists:keyfind(dns_optrr, 1, Additional) of
        #dns_optrr{data = Options} = OptRR ->
            Options1 = Fun(Options),
            OptRR1 = OptRR#dns_optrr{data = Options1},
            Additional1 = lists:keyreplace(dns_optrr, 1, Additional, OptRR1),
            Msg#dns_message{additional = Additional1};
        false ->
            Msg
    end.

-doc "Add an option to the response's OPT RR, if it has one. See `update_options/2`.".
-spec add_option(dns:message(), dns:optrr_elem()) -> dns:message().
add_option(Msg, Option) ->
    update_options(Msg, fun(Options) -> [Option | Options] end).

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

%% Make the query's OPT RR the response's, and move its options to the pipeline opts.
-spec handle_optrr(dns:message(), dns:optrr(), erldns_pipeline:opts()) ->
    erldns_pipeline:return().
handle_optrr(Msg, #dns_optrr{version = Version} = OptRR, #{transport := Transport}) when
    Version > ?DNS_EDNS_MAX_VERSION
->
    OptRR1 = response_optrr(OptRR, Transport),
    {stop, badvers(Msg, OptRR1)};
handle_optrr(Msg, #dns_optrr{data = []} = OptRR, #{transport := Transport}) ->
    with_optrr(Msg, OptRR, Transport);
handle_optrr(Msg, #dns_optrr{data = Options} = OptRR, #{transport := Transport} = Opts) ->
    Msg1 = with_optrr(Msg, OptRR, Transport),
    QueryEdnsOptions = query_edns_options(Options),
    Opts1 = Opts#{query_edns_options => QueryEdnsOptions},
    {Msg1, Opts1}.

%% The query's OPT RR without its options or extended RCODE, and over UDP with the payload size
%% capped.
-spec response_optrr(dns:optrr(), erldns_pipeline:transport()) -> dns:optrr().
response_optrr(#dns_optrr{udp_payload_size = Size} = OptRR, Transport) ->
    Size1 = payload_size(Transport, Size),
    OptRR#dns_optrr{udp_payload_size = Size1, ext_rcode = ?DNS_ERCODE_NOERROR, data = []}.

-spec payload_size(erldns_pipeline:transport(), dns:uint16()) -> dns:uint16().
payload_size(udp, Size) when Size < ?MIN_PACKET_SIZE; ?MAX_PACKET_SIZE < Size ->
    ?MAX_PACKET_SIZE;
payload_size(_, Size) ->
    Size.

%% The response's OPT RR, made from the query's, becomes the only additional record. The header
%% count is set here too, as pipes that stop the pipeline early skip erldns_section_counter. A query
%% whose OPT RR is already the only additional record, and needs no change, is left as it is.
-spec with_optrr(dns:message(), dns:optrr(), erldns_pipeline:transport()) -> dns:message().
with_optrr(
    #dns_message{adc = 1, additional = [OptRR]} = Msg,
    #dns_optrr{udp_payload_size = Size, ext_rcode = ?DNS_ERCODE_NOERROR, data = []} = OptRR,
    Transport
) when Transport =/= udp; ?MIN_PACKET_SIZE =< Size, Size =< ?MAX_PACKET_SIZE ->
    Msg;
with_optrr(Msg, OptRR, Transport) ->
    OptRR1 = response_optrr(OptRR, Transport),
    Msg#dns_message{adc = 1, additional = [OptRR1]}.

%% BADVERS (16) is an extended RCODE of 1 over a header RCODE of 0. The pipeline stops here, so the
%% header counts are set too.
-spec badvers(dns:message(), dns:optrr()) -> dns:message().
badvers(Msg, OptRR) ->
    OptRR1 = OptRR#dns_optrr{version = ?DNS_EDNS_MAX_VERSION, ext_rcode = ?DNS_ERCODE_BADVERS},
    Msg#dns_message{
        qr = true,
        aa = false,
        ad = false,
        rc = ?DNS_RCODE_NOERROR,
        anc = 0,
        auc = 0,
        adc = 1,
        answers = [],
        authority = [],
        additional = [OptRR1]
    }.

%% Folding from the right lets the first option of each code overwrite later ones.
-spec query_edns_options([dns:optrr_elem()]) -> query_edns_options().
query_edns_options(Options) ->
    Add = fun(Option, Acc) ->
        Code = code(Option),
        Acc#{Code => Option}
    end,
    lists:foldr(Add, #{}, Options).

-spec code(dns:optrr_elem()) -> dns:eoptcode() | atom().
code(#dns_opt_llq{}) -> ?DNS_EOPTCODE_LLQ;
code(#dns_opt_ul{}) -> ?DNS_EOPTCODE_UL;
code(#dns_opt_nsid{}) -> ?DNS_EOPTCODE_NSID;
code(#dns_opt_owner{}) -> ?DNS_EOPTCODE_OWNER;
code(#dns_opt_ecs{}) -> ?DNS_EOPTCODE_ECS;
code(#dns_opt_cookie{}) -> ?DNS_EOPTCODE_COOKIE;
code(#dns_opt_ede{}) -> ?DNS_EOPTCODE_EDE;
code(#dns_opt_unknown{id = Code}) -> Code;
%% A record from a newer dns_erlang: crashing here would leave the query's options in the response.
code(Option) -> element(1, Option).
