-module(rr).
-include("include/nsrecs.hrl").
-export([pack_message/1]).

%% Pack the header into its wire format
pack_header(Header) ->
  [Id, Qr, Opcode, Aa, Tc, Rd, Ra, Z, Rcode, Qdcount, Ancount, Nscount, Arcount] = [
    Header#header.id,
    Header#header.qr,
    Header#header.opcode,
    Header#header.aa,
    Header#header.tc,
    Header#header.rd,
    Header#header.ra,
    Header#header.z,
    Header#header.rcode,
    Header#header.qdcount,
    Header#header.ancount,
    Header#header.nscount,
    Header#header.arcount
  ],
  <<Id:16, Qr:1, Opcode:4, Aa:1, Tc:1, Rd:1, Ra:1, Z:3, Rcode:4, Qdcount:16, Ancount:16, Nscount:16, Arcount:16>>.

%% Pack a question into its wire format.
pack_question(Question) ->
  list_to_binary(lists:map(
    fun(Q) ->
        [Qname, Qtype, Qclass] = [string_to_domain_name(Q#question.qname), Q#question.qtype, Q#question.qclass],
        <<Qname/binary, Qtype:16, Qclass:16>>
    end,
  Question)).

%% Pack a message into its binary wire format.
pack_message(Message) ->
  Header = pack_header(Message#message.header),
  Question = pack_question(Message#message.question),
  Answer = pack_records(Message#message.answer),
  Authority = pack_records(Message#message.authority),
  Additional = pack_records(Message#message.additional),
  <<Header/binary, Question/binary, Answer/binary, Authority/binary, Additional/binary>>.

%% Pack a set of records into their wire format.
pack_records(Records) ->
  list_to_binary(lists:map(
    fun(R) ->
        Type = R#rr.type,
        {Rdata, RDLength} = rdata_to_binary(Type, R#rr.rdata),
        [Name, Class, TTL, RData] = [
          string_to_domain_name(R#rr.rname),
          R#rr.class,
          R#rr.ttl,
          Rdata
        ],
        <<Name/binary, Type:16, Class:16, TTL:32, RDLength:16, RData/binary>>
    end,
    Records)).

%% Convert a record data for the given record type to its {binary-representation,length} pair.
rdata_to_binary(Type, Rdata) ->
  case records:type_to_atom(Type) of
    a     -> ipv4_rdata(Rdata);
    aaaa  -> ipv6_rdata(Rdata);
    cname -> domain_rdata(Rdata);
    ns    -> domain_rdata(Rdata);
    mx    -> mx_rdata(Rdata);
    soa   -> soa_rdata(Rdata);
    txt   -> txt_rdata(Rdata);
    spf   -> txt_rdata(Rdata);
    srv   -> srv_rdata(Rdata);
    naptr -> naptr_rdata(Rdata);
    ptr   -> domain_rdata(Rdata);
    _     -> catchall_rdata(Rdata)
  end.

%% Default catchall
catchall_rdata(Rdata) ->
  Value = list_to_binary(Rdata),
  {Value, byte_size(Value)}.

%% Convert record data that is a domain to {binary-representation,length} pair.
domain_rdata(Rdata) ->
  Value = string_to_domain_name(Rdata),
  {Value, byte_size(Value)}.

%% Convert record data for NAPTR records to {binary-representation,length} pair. RFC 2915
naptr_rdata(Rdata) ->
  [OrderStr, PreferenceStr, FlagsStr, ServicesStr, RegexpStr, ReplacementStr] = string:tokens(Rdata, " "),
  {Order, _} = string:to_integer(OrderStr),
  {Preference, _} = string:to_integer(PreferenceStr),
  Flags = character_string(strip_quotes(FlagsStr)),
  Services = character_string(strip_quotes(ServicesStr)),
  Regexp = character_string(strip_quotes(RegexpStr)),
  Replacement = string_to_domain_name(ReplacementStr),
  Value = <<Order:16, Preference:16, Flags/binary, Services/binary, Regexp/binary, Replacement/binary>>,
  {Value, byte_size(Value)}.

%% Convert record data for SRV records to {binary-representation,length} pair. RFC 2782.
srv_rdata(Rdata) ->
  [PriorityStr, WeightStr, PortStr, TargetStr] = string:tokens(Rdata, " "),
  {Priority, _} = string:to_integer(PriorityStr),
  {Weight, _} = string:to_integer(WeightStr),
  {Port, _} = string:to_integer(PortStr),
  Target = string_to_domain_name(TargetStr),
  Value = <<Priority:16, Weight:16, Port:16, Target/binary>>,
  {Value, byte_size(Value)}.

%% Convert record data for TXT records. This function handles both TXT entries with
%% a single text value as well as those with multiple quoted strings in a single TXT
%% entry
txt_rdata(Rdata) ->
  QuoteIndex = string:chr(Rdata, $"),
  io:format("Quote index: ~p~n", [QuoteIndex]),
  case QuoteIndex of
    0 -> single_txt_rdata(Rdata);
    _ -> multi_txt_rdata(Rdata)
  end.

%% Convert TXT rdata with quoted strings into the {binary-representation,length} pair.
multi_txt_rdata(Rdata) ->
  Strings = re:split(Rdata, " \"|\" ", [{return, list}]),
  Value = list_to_binary(lists:map(
    fun(S) ->
      character_string(strip_quotes(S))
    end,
    Strings)),
  {Value, byte_size(Value)}.

%% Convert TXT rdata with a single value into the {binary-representation,length} pair.
single_txt_rdata(Rdata) ->
  Value = character_string(Rdata),
  {Value, byte_size(Value)}.

%% Convert record data for MX records to {binary-representation,length} pair.
mx_rdata(Rdata) ->
  [PriorityStr, HostnameStr] = string:tokens(Rdata, " "),
  {Priority, _} = string:to_integer(PriorityStr),
  Hostname = string_to_domain_name(HostnameStr),
  Value = <<Priority:16, Hostname/binary>>,
  {Value, byte_size(Value)}.

%% Convert SOA record data to {binary-representation,length} pair.
soa_rdata(Rdata) ->
  [MnameStr, RnameStr, SerialStr, RefreshStr, RetryStr, ExpireStr, MinimumStr] = string:tokens(Rdata, " "),
  Mname = string_to_domain_name(MnameStr),
  Rname = string_to_domain_name(RnameStr),
  {Serial, _} = string:to_integer(SerialStr),
  {Refresh, _} = string:to_integer(RefreshStr),
  {Retry, _} = string:to_integer(RetryStr),
  {Expire, _} = string:to_integer(ExpireStr),
  {Minimum, _} = string:to_integer(MinimumStr),
  Value = <<Mname/binary, Rname/binary, Serial:32, Refresh:32, Retry:32, Expire:32, Minimum:32>>,
  {Value, byte_size(Value)}.

%% Convert record data that is an IPv4 address string to {binary-representation,length} pair.
ipv4_rdata(Rdata) ->
  {ok, IPv4Tuple} = inet_parse:address(Rdata),
  IPv4Address = ip_to_binary(IPv4Tuple),
  {IPv4Address, byte_size(IPv4Address)}.

%% Convert record data that is an IPv6 address string to {binary-representation,length} pair. RFC 3596.
ipv6_rdata(Rdata) ->
  {ok, IPv6Tuple} = inet_parse:address(Rdata),
  io:format("IPv6 tuple: ~p~n", [IPv6Tuple]),
  IPv6Address = ipv6_to_binary(IPv6Tuple),
  io:format("IPv6 wire: ~p~n", [IPv6Address]),
  {IPv6Address, byte_size(IPv6Address)}.

%% Convert an IPv6 address to its binary representation
ipv6_to_binary({A,B,C,D,E,F,G,H}) -> <<A,B,C,D,E,F,G,H>>.

%% Convert an IPv4 address to its binary representation
ip_to_binary({A,B,C,D}) -> <<A,B,C,D>>.

%% Remove quotes at the ends of strings
strip_quotes(String) ->
  string:strip(String, both, $").

%% Convert a string to a wire format character_string as defined in RFC 1035
character_string(String) ->
  StringLen = string:len(String),
  StringVal = list_to_binary(String),
  <<StringLen:8, StringVal/binary>>.

%% Convert a string domain name to its binary representation as defined in RFC 1035.
string_to_domain_name(String) ->
  NullLength = 0,
  list_to_binary(
    [lists:map(
        fun(Label) ->
           character_string(Label) 
        end,
        string:tokens(String, ".")
      )|<<NullLength:8>>]
  ).
