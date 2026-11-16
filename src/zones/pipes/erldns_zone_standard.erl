-module(erldns_zone_standard).
-moduledoc """
A zone pipe that decodes the JSON records of the standard DNS types, those `dns_erlang` knows,
into `t:dns:rr/0`.

It leaves the other records as they are, for the pipes after it, and so it does with a record of a
standard type that it can't decode. The pipes after it still get each record as it was given, in
JSON, as the first argument of `c:erldns_zone_pipeline:decode_record/3`.
""".

-behaviour(erldns_zone_pipeline).

-include_lib("dns_erlang/include/dns.hrl").
-include_lib("kernel/include/logger.hrl").

-define(LOG_METADATA, #{domain => [erldns, zones, decoder]}).

-export([decode_record/3]).

-ifdef(TEST).
-export([json_record_to_erlang/1]).
-endif.

-doc "`c:erldns_zone_pipeline:decode_record/3` callback.".
-spec decode_record(Source, Entry, erldns_zone_pipeline:opts()) -> Entry when
    Source :: erldns_zone_pipeline:entry(),
    Entry :: erldns_zone_pipeline:entry().
decode_record(_, #{} = JsonRecord, _Opts) ->
    case standard_record_to_erlang(JsonRecord) of
        not_implemented -> JsonRecord;
        Record -> Record
    end;
decode_record(_, Entry, _Opts) ->
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
