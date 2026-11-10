-module(erldns_edns).
-moduledoc """
Handle the query's OPT RR (RFC 6891).

Put this pipe first in the pipeline.

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

-export([call/2]).
-export([get_opts/1, dnssec_ok/1, get_ede_errors/1]).

-doc "`c:erldns_pipeline:call/2` callback.".
-spec call(dns:message(), erldns_pipeline:opts()) -> dns:message().
call(#dns_message{additional = Additional} = Msg, #{transport := udp}) ->
    case lists:keyfind(dns_optrr, 1, Additional) of
        #dns_optrr{udp_payload_size = Size} = OptRR when
            Size < ?MIN_PACKET_SIZE; ?MAX_PACKET_SIZE < Size
        ->
            OptRR1 = OptRR#dns_optrr{udp_payload_size = ?MAX_PACKET_SIZE},
            Msg#dns_message{additional = lists:keyreplace(dns_optrr, 1, Additional, OptRR1)};
        _ ->
            Msg
    end;
call(Msg, _) ->
    Msg.

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

-doc "Whether the message's OPT RR sets the DO bit (RFC 3225).".
-spec dnssec_ok(dns:message()) -> boolean().
dnssec_ok(#dns_message{additional = Additional}) ->
    case lists:keyfind(dns_optrr, 1, Additional) of
        #dns_optrr{dnssec = DnssecOk} -> DnssecOk;
        false -> false
    end.

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
