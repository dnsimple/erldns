%% Copyright (c) 2012-2020, DNSimple Corporation
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

-module(erldns_handler).
-moduledoc """
The module that handles the resolution of a single DNS question.

The meat of the resolution occurs in erldns_resolver:resolve/3

Emits the following telemetry events:
- `[erldns, handler, handoff]` (span)
- `[erldns, handler, throttle]`
- `[erldns, handler, error]`
- `[erldns, handler, refused]`
- `[erldns, handler, emtpy]`
""".

-behaviour(gen_server).

-include_lib("dns_erlang/include/dns.hrl").
-include_lib("kernel/include/logger.hrl").
-include("erldns.hrl").

-define(DEFAULT_HANDLER_VERSION, 1).

-export([
    start_link/0,
    register_handler/2,
    register_handler/3,
    get_handlers/0,
    get_versioned_handlers/0,
    handle/2
]).
-export([do_handle/2]).
% Gen server hooks
-export([init/1, handle_call/3, handle_cast/2, terminate/2]).
% Internal API
-export([handle_message/2]).

-record(handlers_state, {
    handlers = [] :: [versioned_handler()]
}).
-opaque state() :: #handlers_state{}.
-type versioned_handler() :: {module(), [dns:type()], integer()}.
-type handler() :: {module(), [dns:type()]}.
-export_type([state/0, versioned_handler/0, handler/0]).

-doc "Start the handler registry process".
-spec start_link() -> gen_server:start_ret().
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, noargs, []).

-doc "Register a record handler with the default version of 1".
-spec register_handler([dns:type()], module()) -> ok.
register_handler(RecordTypes, Module) ->
    register_handler(RecordTypes, Module, ?DEFAULT_HANDLER_VERSION).

-doc "Register a record handler with version".
-spec register_handler([dns:type()], module(), integer()) -> ok.
register_handler(RecordTypes, Module, Version) ->
    gen_server:call(?MODULE, {register_handler, RecordTypes, Module, Version}).

-doc "Get all registered handlers of version 1 along with the DNS types they handle".
-spec get_handlers() -> [handler()].
get_handlers() ->
    Handlers = gen_server:call(?MODULE, get_handlers),
    % return only Version 1 handlers
    % strip version information for Version handlers
    [{M, Types} || {M, Types, ?DEFAULT_HANDLER_VERSION} <- Handlers].

-doc "Get all registered handlers along with the DNS types they handle and associated versions".
-spec get_versioned_handlers() -> [versioned_handler()].
get_versioned_handlers() ->
    gen_server:call(?MODULE, get_handlers).

%% If the message has trailing garbage just throw the garbage away and continue
%% trying to process the message.
handle({trailing_garbage, Message, _}, Context) ->
    handle(Message, Context);
%% Handle the message, checking to see if it is throttled.
handle(Message, Context = {_, Host}) when is_record(Message, dns_message) ->
    handle(Message, Host, erldns_query_throttle:throttle(Message, Context));
%% The message was bad so just return it.
%% TODO: consider just throwing away the message
handle(Message, {_, Host}) ->
    ?LOG_ERROR("Received a bad message (module: ~p, event: ~p, message: ~p, host: ~p)", [?MODULE, bad_message, Message, Host]),
    Message.

%% We throttle ANY queries to discourage use of our authoritative name servers
%% for reflection attacks.
%%
%% Note: this should probably be changed to return the original packet without
%% any answer data and with TC bit set to 1.
handle(Message, Host, {throttled, Host, _ReqCount}) ->
    telemetry:execute([erldns, handler, throttle], #{count => 1}, #{}),
    Message#dns_message{
        tc = true,
        aa = true,
        rc = ?DNS_RCODE_NOERROR
    };
%% Message was not throttled, so handle it, then do EDNS handling, optionally
%% append the SOA record if it is a zone transfer and complete the response
%% by filling out count-related header fields.
handle(Message, Host, _) ->
    telemetry:span([erldns, handler, handoff], #{}, fun() ->
        {?MODULE:do_handle(Message, Host), #{}}
    end).

do_handle(Message, Host) ->
    NewMessage = handle_message(Message, Host),
    complete_response(erldns_axfr:optionally_append_soa(NewMessage)).

%% Handle the message by hitting the packet cache and either
%% using the cached packet or continuing with the lookup process.
%%
%% If the cache is missed, then the SOA (Start of Authority) is discovered here.
handle_message(Message, Host) ->
    case erldns_packet_cache:get({Message#dns_message.questions, Message#dns_message.additional}, Host) of
        {ok, CachedResponse} ->
            CachedResponse#dns_message{id = Message#dns_message.id};
        {error, _Reason} ->
            % SOA lookup
            handle_packet_cache_miss(Message, get_authority(Message), Host)
    end.

%% If the packet is not in the cache and we are not authoritative (because there
%% is no SOA record for this zone), then answer immediately setting the AA flag to false.
%% If erldns is configured to use root hints then those will be added to the response.
-spec handle_packet_cache_miss(Message :: dns:message(), AuthorityRecords :: dns:authority(), Host :: dns:ip()) -> dns:message().
handle_packet_cache_miss(Message, [], _Host) ->
    case erldns_config:use_root_hints() of
        true ->
            {Authority, Additional} = erldns_records:root_hints(),
            Message#dns_message{
                aa = false,
                rc = ?DNS_RCODE_REFUSED,
                authority = Authority,
                additional = Additional
            };
        _ ->
            Message#dns_message{aa = false, rc = ?DNS_RCODE_REFUSED}
    end;
%% The packet is not in the cache yet we are authoritative, so try to resolve
%% the request. This is the point the request moves on to the erldns_resolver
%% module.
handle_packet_cache_miss(Message, AuthorityRecords, Host) ->
    safe_handle_packet_cache_miss(Message#dns_message{ra = false}, AuthorityRecords, Host).

-spec safe_handle_packet_cache_miss(Message :: dns:message(), AuthorityRecords :: dns:authority(), Host :: dns:ip()) -> dns:message().
safe_handle_packet_cache_miss(Message, AuthorityRecords, Host) ->
    case application:get_env(erldns, catch_exceptions) of
        {ok, false} ->
            Response = erldns_resolver:resolve(Message, AuthorityRecords, Host),
            maybe_cache_packet(Response, Response#dns_message.aa);
        _ ->
            try erldns_resolver:resolve(Message, AuthorityRecords, Host) of
                Response ->
                    maybe_cache_packet(Response, Response#dns_message.aa)
            catch
                Class:Reason:Stacktrace ->
                    ?LOG_ERROR(#{
                        what => resolve_error,
                        dns_message => Message,
                        class => Class,
                        reason => Reason,
                        stacktrace => Stacktrace
                    }),
                    telemetry:execute([erldns, handler, error], #{count => 1}, #{}),
                    RCode =
                        case Reason of
                            {error, rcode, ?DNS_RCODE_SERVFAIL} -> ?DNS_RCODE_SERVFAIL;
                            {error, rcode, ?DNS_RCODE_NXDOMAIN} -> ?DNS_RCODE_NXDOMAIN;
                            {error, rcode, ?DNS_RCODE_REFUSED} -> ?DNS_RCODE_REFUSED;
                            _ -> ?DNS_RCODE_SERVFAIL
                        end,
                    Message#dns_message{aa = false, rc = RCode}
            end
    end.

%% We are authoritative so cache the packet and return the message.
maybe_cache_packet(Message, true) ->
    erldns_packet_cache:put({Message#dns_message.questions, Message#dns_message.additional}, Message),
    Message;
%% We are not authoritative so just return the message.
maybe_cache_packet(Message, false) ->
    Message.

%% Get the SOA authority for the current query.
get_authority(MessageOrName) ->
    case erldns_zone_cache:get_authority(MessageOrName) of
        {ok, Authority} ->
            Authority;
        {error, _} ->
            []
    end.

%% Update the message counts and set the QR flag to true.
complete_response(Message) ->
    notify_empty_response(Message#dns_message{
        anc = length(Message#dns_message.answers),
        auc = length(Message#dns_message.authority),
        adc = length(Message#dns_message.additional),
        qr = true
    }).

notify_empty_response(Message) ->
    case {Message#dns_message.rc, Message#dns_message.anc + Message#dns_message.auc + Message#dns_message.adc} of
        {?DNS_RCODE_REFUSED, _} ->
            telemetry:execute([erldns, handler, refused], #{count => 1}, #{}),
            Message;
        {_, 0} ->
            ?LOG_INFO("Empty response (module: ~p, event: ~p, message: ~p)", [?MODULE, empty_response, Message]),
            telemetry:execute([erldns, handler, empty], #{count => 1}, #{}),
            Message;
        _ ->
            Message
    end.

% gen_server callbacks
-doc false.
-spec init(noargs) -> {ok, state()}.
init(noargs) ->
    {ok, #handlers_state{}}.

-doc false.
-spec handle_call
    ({register_handler, [dns:type()], module(), integer()}, gen_server:from(), state()) ->
        {reply, ok, state()};
    (get_handlers, gen_server:from(), state()) ->
        {reply, [versioned_handler()], state()}.
handle_call({register_handler, RecordTypes, Module, Version}, _, State) ->
    ?LOG_INFO("Registered handler (module: ~p, types: ~p, version: ~p)", [Module, RecordTypes, Version]),
    NewHandlers = [{Module, RecordTypes, Version} | State#handlers_state.handlers],
    {reply, ok, State#handlers_state{handlers = NewHandlers}};
handle_call(get_handlers, _, State) ->
    {reply, State#handlers_state.handlers, State}.

-doc false.
-spec handle_cast(term(), state()) -> {noreply, state()}.
handle_cast(_, State) ->
    {noreply, State}.

-doc false.
-spec terminate(term(), state()) -> any().
terminate(_, _) ->
    erldns_storage:delete_table(handler_registry).
