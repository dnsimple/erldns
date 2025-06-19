-module(erldns_edns).
-moduledoc false.

-include_lib("dns_erlang/include/dns_records.hrl").

-export([get_opts/1]).

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
