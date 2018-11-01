%% Copyright (c) 2012-2018, DNSimple Corporation
%%
%% Permission to use, copy, modify, and/or distribute this software for any
%% purpose with or without fee is hereby granted, provided that the above
%% copyright notice and this permission notice appear in all copies.
%%
%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
%% WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
%% MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
%% ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
%% WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
%% ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
%% OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

%% @doc A process that maintains a collection of encoders in its state
%% for encoding zones from their Erlang representation to JSON.
-module(erldns_zone_encoder).

-behavior(gen_server).

-include_lib("dns/include/dns.hrl").
-include("erldns.hrl").

-export([start_link/0]).
-export([zone_to_json/1, register_encoders/1, register_encoder/1]).

% Gen server hooks
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3
        ]).

-define(SERVER, ?MODULE).

-record(state, {encoders}).

% Public API

%% @doc Start the encoder process.
-spec start_link() -> any().
start_link() ->
  gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% @doc Encode a Zone record into JSON.
-spec zone_to_json(#zone{}) -> binary().
zone_to_json(Zone) ->
  gen_server:call(?SERVER, {encode_zone, Zone}).

%% @doc Register a list of encoder modules.
-spec register_encoders([module()]) -> ok.
register_encoders(Modules) ->
  lager:info("Registering custom encoders (modules: ~p)", [Modules]),
  gen_server:call(?SERVER, {register_encoders, Modules}).

%% @doc Register a single encoder module.
-spec register_encoder(module()) -> ok.
register_encoder(Module) ->
  lager:info("Registering customer encoder (module: ~p)", [Module]),
  gen_server:call(?SERVER, {register_encoder, Module}).


% Gen server hooks

init([]) ->
  {ok, #state{encoders = []}}.

handle_call({encode_zone, Zone}, _From, State) ->
  {reply, zone_to_json(Zone, State#state.encoders), State};

handle_call({register_encoders, Modules}, _From, State) ->
  {reply, ok, State#state{encoders = State#state.encoders ++ Modules}};

handle_call({register_encoder, Module}, _From, State) ->
  {reply, ok, State#state{encoders = State#state.encoders ++ [Module]}}.

handle_cast(_, State) ->
  {noreply, State}.

handle_info(_, State) ->
  {noreply, State}.

terminate(_, _State) ->
  ok.

code_change(_, State, _) ->
  {ok, State}.


% Internal API

zone_to_json(Zone, Encoders) ->
  Records = records_to_json(Zone, Encoders),
  FilteredRecords = lists:filter(record_filter(), Records),
  jsx:encode([{<<"erldns">>,
               [
                {<<"zone">>, [
                              {<<"name">>, Zone#zone.name},
                              {<<"version">>, Zone#zone.version},
                              {<<"records">>, FilteredRecords}
                              % Note: Private key material is purposely omitted
                             ]}
               ]
              }]).

record_filter() ->
  fun(R) ->
      case R of
        [] -> false;
        {} -> false;
        _ -> true
      end
  end.

records_to_json(Zone, Encoders) ->
  lists:map(encode(Encoders), Zone#zone.records).

encode(Encoders) ->
  fun(Record) ->
      encode_record(Record, Encoders)
  end.

encode_record(Record, Encoders) ->
  lager:debug("Encoding record (record: ~p)", [Record]),
  case encode_record(Record) of
    [] ->
      lager:debug("Trying custom encoders (encoders: ~p)", [Encoders]),
      try_custom_encoders(Record, Encoders);
    EncodedRecord -> EncodedRecord
  end.

encode_record({dns_rr, Name, _, Type = ?DNS_TYPE_SOA, Ttl, Data}) ->
  encode_record(Name, Type, Ttl, Data);
encode_record({dns_rr, Name, _, Type = ?DNS_TYPE_NS, Ttl, Data}) ->
  encode_record(Name, Type, Ttl, Data);
encode_record({dns_rr, Name, _, Type = ?DNS_TYPE_A, Ttl, Data}) ->
  encode_record(Name, Type, Ttl, Data);
encode_record({dns_rr, Name, _, Type = ?DNS_TYPE_AAAA, Ttl, Data}) ->
  encode_record(Name, Type, Ttl, Data);
encode_record({dns_rr, Name, _, Type = ?DNS_TYPE_CNAME, Ttl, Data}) ->
  encode_record(Name, Type, Ttl, Data);
encode_record({dns_rr, Name, _, Type = ?DNS_TYPE_MX, Ttl, Data}) ->
  encode_record(Name, Type, Ttl, Data);
encode_record({dns_rr, Name, _, Type = ?DNS_TYPE_HINFO, Ttl, Data}) ->
  encode_record(Name, Type, Ttl, Data);
encode_record({dns_rr, Name, _, Type = ?DNS_TYPE_TXT, Ttl, Data}) ->
  encode_record(Name, Type, Ttl, Data);
encode_record({dns_rr, Name, _, Type = ?DNS_TYPE_SPF, Ttl, Data}) ->
  encode_record(Name, Type, Ttl, Data);
encode_record({dns_rr, Name, _, Type = ?DNS_TYPE_SSHFP, Ttl, Data}) ->
  encode_record(Name, Type, Ttl, Data);
encode_record({dns_rr, Name, _, Type = ?DNS_TYPE_SRV, Ttl, Data}) ->
  encode_record(Name, Type, Ttl, Data);
encode_record({dns_rr, Name, _, Type = ?DNS_TYPE_NAPTR, Ttl, Data}) ->
  encode_record(Name, Type, Ttl, Data);
encode_record({dns_rr, Name, _, Type = ?DNS_TYPE_CAA, Ttl, Data}) ->
  encode_record(Name, Type, Ttl, Data);
encode_record({dns_rr, Name, _, Type = ?DNS_TYPE_DS, Ttl, Data}) ->
  encode_record(Name, Type, Ttl, Data);
encode_record({dns_rr, Name, _, Type = ?DNS_TYPE_CDS, Ttl, Data}) ->
  encode_record(Name, Type, Ttl, Data);
encode_record({dns_rr, Name, _, Type = ?DNS_TYPE_DNSKEY, Ttl, Data}) ->
  encode_record(Name, Type, Ttl, Data);
encode_record({dns_rr, Name, _, Type = ?DNS_TYPE_CDNSKEY, Ttl, Data}) ->
  encode_record(Name, Type, Ttl, Data);
encode_record({dns_rr, Name, _, Type = ?DNS_TYPE_RRSIG, Ttl, Data}) ->
  encode_record(Name, Type, Ttl, Data);
encode_record(Record) ->
  lager:warning("Unable to encode record (record: ~p)", [Record]),
  [].

encode_record(Name, Type, Ttl, Data) ->
  [
   {<<"name">>, erlang:iolist_to_binary(io_lib:format("~s.", [Name]))},
   {<<"type">>, dns:type_name(Type)},
   {<<"ttl">>, Ttl},
   {<<"content">>, encode_data(Data)}
  ].


try_custom_encoders(_Record, []) ->
  {};
try_custom_encoders(Record, [Encoder|Rest]) ->
  lager:debug("Trying custom encoder (encoder: ~p)", [Encoder]),
  case Encoder:encode_record(Record) of
    [] -> try_custom_encoders(Record, Rest);
    EncodedData -> EncodedData
  end.

encode_data({dns_rrdata_soa, Mname, Rname, Serial, Refresh, Retry, Expire, Minimum}) ->
  erlang:iolist_to_binary(io_lib:format("~s. ~s. (~w ~w ~w ~w ~w)", [Mname, Rname, Serial, Refresh, Retry, Expire, Minimum]));
encode_data({dns_rrdata_ns, Dname}) ->
  erlang:iolist_to_binary(io_lib:format("~s.", [Dname]));
encode_data({dns_rrdata_a, Address}) ->
  list_to_binary(inet_parse:ntoa(Address));
encode_data({dns_rrdata_aaaa, Address}) ->
  list_to_binary(inet_parse:ntoa(Address));
encode_data({dns_rrdata_caa, Flags, Tag, Value}) ->
  erlang:iolist_to_binary(io_lib:format("~w ~s \"~s\"", [Flags, Tag, Value]));
encode_data({dns_rrdata_cname, Dname}) ->
  erlang:iolist_to_binary(io_lib:format("~s.", [Dname]));
encode_data({dns_rrdata_mx, Preference, Dname}) ->
  erlang:iolist_to_binary(io_lib:format("~w ~s.", [Preference, Dname]));
encode_data({dns_rrdata_hinfo, Cpu, Os}) ->
  erlang:iolist_to_binary(io_lib:format("~w ~w", [Cpu, Os]));
% RP
encode_data({dns_rrdata_txt, Text}) ->
  erlang:iolist_to_binary(io_lib:format("~s", [Text]));
encode_data({dns_rrdata_spf, [Data]}) ->
  erlang:iolist_to_binary(io_lib:format("~s", [Data]));
encode_data({dns_rrdata_sshfp, Alg, Fptype, Fp}) ->
  erlang:iolist_to_binary(io_lib:format("~w ~w ~s", [Alg, Fptype, Fp]));
encode_data({dns_rrdata_srv, Priority, Weight, Port, Dname}) ->
  erlang:iolist_to_binary(io_lib:format("~w ~w ~w ~s.", [Priority, Weight, Port, Dname]));
encode_data({dns_rrdata_naptr, Order, Preference, Flags, Services, Regexp, Replacements}) ->
  erlang:iolist_to_binary(io_lib:format("~w ~w ~s ~s ~s ~s", [Order, Preference, Flags, Services, Regexp, Replacements]));
encode_data({dns_rrdata_ds, Keytag, Alg, DigestType, Digest}) ->
  erlang:iolist_to_binary(io_lib:format("~w ~w ~w ~s", [Keytag, Alg, DigestType, Digest]));
encode_data({dns_rrdata_cds, Keytag, Alg, DigestType, Digest}) ->
  erlang:iolist_to_binary(io_lib:format("~w ~w ~w ~s", [Keytag, Alg, DigestType, Digest]));
encode_data({dns_rrdata_dnskey, Flags, Protocol, Alg, Key, KeyTag}) ->
  erlang:iolist_to_binary(io_lib:format("~w ~w ~w ~w ~w", [Flags, Protocol, Alg, Key, KeyTag]));
encode_data({dns_rrdata_cdnskey, Flags, Protocol, Alg, Key, KeyTag}) ->
  erlang:iolist_to_binary(io_lib:format("~w ~w ~w ~w ~w", [Flags, Protocol, Alg, Key, KeyTag]));
encode_data({dns_rrdata_rrsig, TypeCovered, Alg, Labels, OriginalTtl, Expiration, Inception, KeyTag, SignersName, Signature}) ->
  erlang:iolist_to_binary(io_lib:format("~w ~w ~w ~w ~w ~w ~w ~w ~s", [TypeCovered, Alg, Labels, OriginalTtl, Expiration, Inception, KeyTag, SignersName, Signature]));
encode_data(Data) ->
  lager:debug("Unable to encode rrdata (data: ~p)", [Data]),
  {}.
