-module(erldns_unpack).
-include("include/nsrecs.hrl").
-export([unpack/1]).

unpack_header(Request) when is_binary(Request) ->
  <<Id:16, Qr:1, Opcode:4, Aa:1, Tc:1, Rd:1, Ra:1, Z:3, Rcode:4, Qdcount:16, Ancount:16, Nscount:16, Arcount:16, Rest/binary>> = Request,
  Header = #header{id=Id,
    qr=Qr,
    opcode=Opcode,
    aa=Aa,
    tc=Tc,
    rd=Rd,
    ra=Ra,
    z=Z,
    rcode=Rcode,
    qdcount=Qdcount,
    ancount=Ancount,
    nscount=Nscount,
    arcount=Arcount},
  [ Rest, Header ].


%% Utility function to parse qname from a question part.
%%
%% qname is made up of 1 or more labels that make up the dot parts of a domain
%% in most cases. They are encoded with 1 octet describing the length of a label
%% followed by the declared number of octets. When a length of 0 is reached then
%% parsing is complete and you can put the full domain together by reversing the
%% list and joining each part with a ".".
parse_qname(Data) -> 
  <<Len:8, Rest/binary>> = Data,
  parse_qname(Len, Rest, []).

parse_qname(0, Data, Name) -> [Data, Name];
parse_qname(Len, Data, Acc) ->
  <<Label:Len/binary, NextLen:8, Rest/binary>> = Data,
  parse_qname(NextLen, Rest, lists:concat([Acc,".",binary_to_list(Label)])).

%% Unpack question part.
%%
%% The question is made up of a multi part qname (see parse_qname above), a 16
%% bit qtype, and a 16 bit qclass.
unpack_question(Data, Count) ->
  unpack_question(Data, Count, []).

unpack_question(Data, 0, Acc) ->
  [ Data, Acc ];
unpack_question(Data, Count, Acc) ->
  [R1, Qname] = parse_qname(Data),
  <<Qtype:16, Qclass:16, R2/binary>> = R1,
  Question = #question{qname=Qname,qtype=Qtype,qclass=Qclass},
  unpack_question(R2, Count-1, [Question|Acc]).


%% Unpack a DNS request.
%%
%% A DNS request (and response) is made up of the following components:
%%
%%   header
%%   question
%%   answer
%%   authority
%%   additional
%%
%% Typically when unpacking, only the header and question will have any useful
%% content. The next three parts are to be generated for the response back to
%% the requestor.
unpack(Request) when is_binary(Request) ->
  [R1, Header] = unpack_header(Request),
  [_, Question] = unpack_question(R1, Header#header.qdcount),
  #message{header=Header,question=Question}.
