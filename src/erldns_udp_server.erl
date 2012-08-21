-module(erldns_udp_server).

-include("dns_records.hrl").

-behavior(gen_server).

% API
-export([start_link/0]).

% Gen server hooks
-export([init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3
  ]).

-define(SERVER, ?MODULE).
-define(MAX_PACKET_SIZE, 512).

-record(state, {}).

%% Public API
start_link() ->
  gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% gen_server hooks
init(_Args) ->
  {ok, Port} = application:get_env(erldns, port),
  spawn(fun() -> start(Port) end),
  {ok, #state{}}.
handle_call(_Request, _From, State) ->
  {ok, State}.
handle_cast(_Message, State) ->
  {noreply, State}.
handle_info(_Message, State) ->
  {noreply, State}.
terminate(_Reason, _State) ->
  ok.
code_change(_PreviousVersion, State, _Extra) ->
  {ok, State}.

%% Internal functions
%% Start a UDP server.
start(Port) ->
  random:seed(erlang:now()),
  case gen_udp:open(Port, [binary]) of
    {ok, Socket} -> 
      lager:info("UDP server opened socket: ~p~n", [Socket]),
      loop(Socket);
    {error, eacces} ->
      lager:error("Failed to open UDP socket. Need to run as sudo?"),
      {error, eacces}
  end.

%% Loop for accepting UDP requests
loop(Socket) ->
  lager:info("Awaiting Request~n"),
  receive
    {udp, Socket, Host, Port, Bin} ->
      lager:info("Received UDP Request~n"),
      spawn(fun() -> handle_dns_query(Socket, Host, Port, Bin) end),
      loop(Socket)
  end.

%% Handle DNS query that comes in over UDP
handle_dns_query(Socket, Host, Port, Bin) ->
  lager:info("Message from from ~p~n", [Host]),
  DecodedMessage = dns:decode_message(Bin),
  lager:info("Decoded message ~p~n", [DecodedMessage]),
  NewResponse = handle_additional_processing(erldns_handler:handle(DecodedMessage)),
  BinReply = dns:encode_message(NewResponse),
  BinLength = byte_size(BinReply),
  lager:info("Response packet size: ~p", [BinLength]),
  OptionallyTruncatedBinReply = case BinLength > max_payload_size(NewResponse) of
    true -> dns:encode_message(truncate(NewResponse));
    false -> BinReply
  end,
  gen_udp:send(Socket, Host, Port, OptionallyTruncatedBinReply).

max_payload_size(Message) ->
  case Message#dns_message.additional of
    [Opt|_] ->
      case Opt#dns_optrr.udp_payload_size of
        [] -> ?MAX_PACKET_SIZE;
        _ -> Opt#dns_optrr.udp_payload_size
      end;
    _ -> ?MAX_PACKET_SIZE
  end.

%% Truncate the message for UDP packet limitations (at least that
%% is what it may eventually do. Right now it simply sets the
%% tc bit to indicate the message was truncated.
truncate(Message) ->
  %Response = erldns_handler:build_response(Message#dns_message.answers, Message),
  Message#dns_message{tc = true}.

%% Handle EDNS processing (includes DNSSEC?)
handle_additional_processing(Message) ->
  handle_opts(Message, Message#dns_message.additional).

handle_opts(Message, []) ->
  Message;
handle_opts(Message, [Opt|Rest]) ->
  lager:info("Opt: ~p", [Opt]),
  handle_opts(Message, Rest).
