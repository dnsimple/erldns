-module(erldns_zone_codec).
-moduledoc """
Encoding and decoding of zone data in JSON format.

To write custom codecs, you need to implement the callbacks exposed by this module,
and register the codec in the configuration.

## Configuration

```erlang
{erldns, [
    {zones, #{
        codecs => [sample_custom_zone_codec]
    }},
]}
```

## Custom codecs

```erlang
-module(sample_custom_zone_codec).
-behaviour(erldns_zone_codec).

-include_lib("dns_erlang/include/dns.hrl").
-include_lib("erldns/include/erldns.hrl").

-export([decode/1, encode/1]).

-define(DNS_TYPE_SAMPLE, 40000).

decode(#{~"name" := Name, ~"type" := ~"SAMPLE", ~"ttl" := Ttl, ~"data" := Data}) ->
    #dns_rr{
        name = Name,
        type = ?DNS_TYPE_SAMPLE,
        data = maps:get(~"dname", Data),
        ttl = Ttl
    };
decode(_) ->
    not_implemented.

encode(#dns_rr{name = Name, type = ?DNS_TYPE_SAMPLE, ttl = Ttl, data = Data}) ->
    #{
        ~"name" => Name,
        ~"type" => ~"SAMPLE",
        ~"ttl" => Ttl,
        ~"content" => erlang:iolist_to_binary(io_lib:format("~s", [Data]))
    };
encode(_) ->
    not_implemented.
```
""".

-behaviour(gen_server).

-include_lib("dns_erlang/include/dns.hrl").
-include_lib("kernel/include/logger.hrl").
-include_lib("erldns/include/erldns.hrl").

-export([
    build_zone/4,
    encode/1,
    encode/2,
    decode/1,
    register_codecs/1,
    register_codec/1,
    list_codecs/0
]).

-export([start_link/0, init/1, handle_call/3, handle_cast/2, terminate/2]).

-type encoder() :: fun((dns:rr()) -> not_implemented | json:encode_value()).
-type decoder() :: fun((dynamic()) -> not_implemented | dns:rr()).
-callback encode(dns:rr()) -> not_implemented | json:encode_value().
-callback decode(json:encode_value()) -> not_implemented | dns:rr().
-export_type([encoder/0, decoder/0]).

-record(state, {
    encoders :: [encoder()],
    decoders :: [decoder()]
}).
-type state() :: #state{}.
-export_type([state/0]).

-spec build_zone(dns:dname(), binary(), [dns:rr()], [erldns:keyset()]) -> erldns:zone().
build_zone(Name, Version, Records, Keys) ->
    NormalizedName = dns:dname_to_lower(Name),
    Authorities = lists:filter(erldns_records:match_type(?DNS_TYPE_SOA), Records),
    #zone{
        name = NormalizedName,
        version = Version,
        record_count = length(Records),
        authority = Authorities,
        records = Records,
        keysets = Keys
    }.

-doc #{equiv => encode(Zone, #{mode => zone_to_json})}.
-spec encode(erldns:zone()) -> json:encode_value().
encode(Zone) ->
    encode(Zone, #{mode => zone_to_json}).

-doc "Takes a zone and turns it into a map.".
-spec encode(erldns:zone(), #{atom() => dynamic()}) -> json:encode_value().
encode(Zone, Opts) ->
    {Encoders, _} = list_codecs(),
    erldns_zone_encoder:encode(Zone, Opts, Encoders).

-doc "Takes a JSON map and turns it into a zone.".
-spec decode(json:decode_value()) -> erldns:zone().
decode(Zone) ->
    {_, Decoders} = list_codecs(),
    erldns_zone_parser:decode(Zone, Decoders).

-doc "Register a custom parser module.".
-spec register_codec(module()) -> ok.
register_codec(Module) when is_atom(Module) ->
    register_codecs([Module]).

-doc "Register a list of custom parser modules.".
-spec register_codecs([module()]) -> ok.
register_codecs(Modules) when is_list(Modules) ->
    ?LOG_NOTICE(
        #{what => registering_custom_parsers, parsers => Modules},
        #{domain => [erldns, zones]}
    ),
    gen_server:call(?MODULE, {register_codecs, Modules}, 5000).

-doc "Get the list of registered zone parsers.".
-spec list_codecs() -> {[encoder()], [decoder()]}.
list_codecs() ->
    persistent_term:get(?MODULE, {[], []}).

% Internal API
-doc false.
-spec start_link() -> gen_server:start_ret().
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, noargs, [{hibernate_after, 0}]).

-doc false.
-spec init(noargs) -> {ok, state()}.
init(noargs) ->
    process_flag(trap_exit, true),
    {Encoders, Decoders} = prepare_codecs(),
    persistent_term:put(?MODULE, {Encoders, Decoders}),
    {ok, #state{encoders = Encoders, decoders = Decoders}}.

-doc false.
-spec handle_call(dynamic(), gen_server:from(), state()) ->
    {reply, dynamic(), state()}.
handle_call({register_codecs, Modules}, _From, State) ->
    {NewEncoders, NewDecoders} = prepare_codecs(Modules),
    Encoders = State#state.encoders ++ NewEncoders,
    Decoders = State#state.decoders ++ NewDecoders,
    persistent_term:put(?MODULE, {Encoders, Decoders}),
    {reply, ok, #state{encoders = Encoders, decoders = Decoders}};
handle_call(Call, From, State) ->
    ?LOG_INFO(#{what => unexpected_call, from => From, call => Call}, #{domain => [erldns, zones]}),
    {reply, not_implemented, State}.

-doc false.
-spec handle_cast(dynamic(), state()) -> {noreply, state()}.
handle_cast(Cast, State) ->
    ?LOG_INFO(#{what => unexpected_cast, cast => Cast}, #{domain => [erldns, zones]}),
    {noreply, State}.

-doc false.
-spec terminate(term(), state()) -> term().
terminate(_, _) ->
    persistent_term:erase(?MODULE).

-spec prepare_codecs() -> {[encoder()], [decoder()]}.
prepare_codecs() ->
    ZonesConfig = application:get_env(erldns, zones, #{}),
    prepare_codecs(ZonesConfig).

-spec prepare_codecs(erldns_zones:config()) -> {[encoder()], [decoder()]}.
prepare_codecs(#{codecs := Modules}) ->
    lists:foldr(
        fun(Module, {AccEncoders, AccDecoders}) ->
            maybe
                {module, Module} ?= code:ensure_loaded(Module),
                true ?= erlang:function_exported(Module, encode, 1),
                true ?= erlang:function_exported(Module, decode, 1),
                Encoders = [fun Module:encode/1 | AccEncoders],
                Decoders = [fun Module:decode/1 | AccDecoders],
                {Encoders, Decoders}
            else
                {error, Reason} ->
                    erlang:error({badcodec, {module, Reason}});
                false ->
                    erlang:error({badcodec, {module_does_not_export_call, Module}})
            end
        end,
        {[], []},
        Modules
    );
prepare_codecs(#{}) ->
    {[], []}.
