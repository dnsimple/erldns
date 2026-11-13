-module(erldns_zone_standard).
-moduledoc """
A zone pipe that decodes the JSON records of the standard DNS types, those `dns_erlang` knows,
into `t:dns:rr/0`.

It leaves the other records as they are, for the pipes after it, and so it does with a record of a
standard type that it can't decode. Pipes that need to see the records of standard types as JSON go
before it.
""".

-behaviour(erldns_zone_pipeline).

-include_lib("dns_erlang/include/dns.hrl").
-include_lib("kernel/include/logger.hrl").

-define(LOG_METADATA, #{domain => [erldns, zones, decoder]}).

-export([call/2]).

-ifdef(TEST).
-export([json_record_to_erlang/1]).
-endif.

-doc "`c:erldns_zone_pipeline:call/2` callback.".
-spec call([erldns_zone_pipeline:entry()], erldns_zone_pipeline:opts()) ->
    [erldns_zone_pipeline:entry()].
call(Entries, _Opts) ->
    [decode(Entry) || Entry <- Entries].

decode(#{} = JsonRecord) ->
    case standard_record_to_erlang(JsonRecord) of
        not_implemented -> JsonRecord;
        Record -> Record
    end;
decode(Entry) ->
    Entry.

-spec standard_record_to_erlang(dynamic()) -> not_implemented | dns:rr().
standard_record_to_erlang(#{~"type" := TypeBin} = JsonRecord) when
    is_binary(TypeBin), ~"" =/= TypeBin
->
    case dns_names:name_type(TypeBin) of
        undefined ->
            case all_digits(TypeBin) of
                true -> json_record_to_erlang(JsonRecord);
                false -> not_implemented
            end;
        _KnownType ->
            json_record_to_erlang(JsonRecord)
    end;
standard_record_to_erlang(_JsonRecord) ->
    not_implemented.

%% Matched on bytes rather than through `string:to_integer/1',
%% which walks the binary as unicode graphemes.
-spec all_digits(binary()) -> boolean().
all_digits(<<C, Rest/binary>>) when $0 =< C, C =< $9 ->
    all_digits(Rest);
all_digits(~"") ->
    true;
all_digits(_) ->
    false.

-spec json_record_to_erlang(dynamic()) -> not_implemented | dns:rr().
json_record_to_erlang(#{~"name" := _, ~"type" := _, ~"ttl" := _, ~"data" := Data} = JsonRecord) when
    Data =/= null
->
    try
        RR = #dns_rr{} = dns_json:from_map(JsonRecord),
        case RR#dns_rr.type of
            ?DNS_TYPE_DNSKEY -> dnssec:add_keytag_to_dnskey(RR);
            ?DNS_TYPE_CDNSKEY -> dnssec:add_keytag_to_cdnskey(RR);
            _ -> RR
        end
    catch
        error:{invalid_ipv4_in_json, _, _} = Reason:Stacktrace ->
            erlang:raise(error, Reason, Stacktrace);
        error:{invalid_ipv6_in_json, _, _} = Reason:Stacktrace ->
            erlang:raise(error, Reason, Stacktrace);
        error:{svcb_mandatory_validation_error, _} = Reason:Stacktrace ->
            erlang:raise(error, Reason, Stacktrace);
        Class:Reason:Stacktrace ->
            ?LOG_DEBUG(
                #{
                    what => from_map_failed,
                    class => Class,
                    reason => Reason,
                    stacktrace => Stacktrace,
                    record => JsonRecord
                },
                ?LOG_METADATA
            ),
            not_implemented
    end;
json_record_to_erlang(#{}) ->
    not_implemented.
