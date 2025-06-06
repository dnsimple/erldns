-module(erldns_zone_codec).
-moduledoc """
Encoding and decoding of zone data in JSON format.
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

-doc #{equiv => encode(Zone, #{})}.
-spec encode(dynamic() | erldns:zone()) -> json:encode_value().
encode(Zone) ->
    encode(Zone, #{}).

-doc "Takes a zone and turns it into a map.".
-spec encode(dynamic() | erldns:zone(), map()) -> json:encode_value().
encode(Zone, Opts) ->
    {Encoders, _} = list_codecs(),
    erldns_zone_encoder:encode(Zone, Opts, Encoders).

-doc "Takes a JSON zone and turns it into `{Name, Sha, Records, KeySet}` tuples.".
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
    ?LOG_NOTICE(#{what => registering_custom_parsers, parsers => Modules}),
    gen_server:call(?MODULE, {register_codecs, Modules}).

-doc "Get the list of registered zone parsers.".
-spec list_codecs() -> {[encoder()], [decoder()]}.
list_codecs() ->
    persistent_term:get(?MODULE, []).

% Internal API
-doc false.
-spec start_link() -> gen_server:start_ret().
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, noargs, [{hibernate_after, 0}]).

-doc false.
-spec init(noargs) -> {ok, state()}.
init(noargs) ->
    process_flag(trap_exit, true),
    CustomCodecs = application:get_env(erldns, custom_zone_json_codecs, []),
    Encoders = [fun Module:encode/1 || Module <- CustomCodecs],
    Decoders = [fun Module:decode/1 || Module <- CustomCodecs],
    persistent_term:put(?MODULE, {Encoders, Decoders}),
    {ok, #state{encoders = Encoders, decoders = Decoders}}.

-doc false.
-spec handle_call(dynamic(), gen_server:from(), state()) ->
    {reply, dynamic(), state()}.
handle_call({register_codecs, Modules}, _From, State) ->
    Encoders = [fun Module:encode/1 || Module <- Modules],
    NewEncoders = State#state.encoders ++ Encoders,
    Decoders = [fun Module:decode/1 || Module <- Modules],
    NewDecoders = State#state.decoders ++ Decoders,
    persistent_term:put(?MODULE, {NewEncoders, NewDecoders}),
    {reply, ok, #state{encoders = NewEncoders, decoders = NewDecoders}};
handle_call(Call, From, State) ->
    ?LOG_INFO(#{what => unexpected_call, from => From, call => Call}),
    {reply, not_implemented, State}.

-doc false.
-spec handle_cast(dynamic(), state()) -> {noreply, state()}.
handle_cast(Cast, State) ->
    ?LOG_INFO(#{what => unexpected_cast, cast => Cast}),
    {noreply, State}.

-spec terminate(term(), state()) -> any().
terminate(_, _) ->
    persistent_term:erase(?MODULE).
