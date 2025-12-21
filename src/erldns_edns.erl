-module(erldns_edns).
-moduledoc false.

-include_lib("dns_erlang/include/dns_records.hrl").

-export([get_opts/1, get_ede_errors/1]).

%% Get a property list of EDNS0 options.
%%
%% Supported options are:
%%
%% * {dnssec, true}
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
