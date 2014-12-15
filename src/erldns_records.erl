%% Copyright (c) 2012-2014, Aetrion LLC
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

%% Functions related to DNS records.
-module(erldns_records).

-include_lib("dns/include/dns.hrl").

-export([optionally_convert_wildcard/2,
         wildcard_qname/1,
         default_ttl/1,
         default_priority/1,
         name_type/1,
         root_hints/0,
         minimum_soa_ttl/2,
         match_type/1,
         match_types/1,
         match_wildcard/0,
         match_glue/1,
         replace_name/1]).

%% If the name returned from the DB is a wildcard name then the
%% Original Qname needs to be returned in its place.
optionally_convert_wildcard(Name, Qname) ->
    [Head|_] = dns:dname_to_labels(Name),
    case Head of
        <<"*">> -> Qname;
        _ -> Name
    end.

%% Get a wildcard variation of a Qname. Replaces the leading
%% label with an asterisk for wildcard lookup.
wildcard_qname(Qname) ->
    [_|Rest] = dns:dname_to_labels(Qname),
    dns:labels_to_dname([<<"*">>] ++ Rest).

%% Return the TTL value or 3600 if it is undefined.
default_ttl(TTL) ->
    case TTL of
        undefined -> 3600;
        Value -> Value
    end.

%% Return the Priority value or 0 if it is undefined.
default_priority(Priority) ->
    case Priority of
        undefined -> 0;
        Value -> Value
    end.

%% Applies a minimum TTL based on the SOA minumum value.
minimum_soa_ttl(Record, Data) when is_record(Data, dns_rrdata_soa) ->
    Record#dns_rr{ttl = erlang:min(Data#dns_rrdata_soa.minimum, Record#dns_rr.ttl)};
minimum_soa_ttl(Record, _) -> Record.



%% Various matching functions.
match_type(Type) ->
    fun(R) when is_record(R, dns_rr) ->
            R#dns_rr.type =:= Type
    end.

match_types(Types) ->
    fun(R) when is_record(R, dns_rr) ->
            lists:any(fun(T) -> R#dns_rr.type =:= T end, Types)
    end.

match_wildcard() ->
    fun(R) when is_record(R, dns_rr) ->
            lists:any(
              fun(L) ->
                      L =:= <<"*">>
              end, dns:dname_to_labels(R#dns_rr.name))
    end.

match_glue(Name) ->
    fun(R) when is_record(R, dns_rr) ->
            R#dns_rr.data =:= #dns_rrdata_ns{dname=Name}
    end.



%% Replacement functions.
replace_name(Name) -> fun(R) when is_record(R, dns_rr) -> R#dns_rr{name = Name} end.

%% @doc Returns the type value given a binary string.
-spec name_type(binary()) -> dns:type() | 'undefined'.
name_type(Type) when is_binary(Type) ->
    case Type of
        ?DNS_TYPE_A_BSTR -> ?DNS_TYPE_A_NUMBER;
        ?DNS_TYPE_NS_BSTR -> ?DNS_TYPE_NS_NUMBER;
        ?DNS_TYPE_MD_BSTR -> ?DNS_TYPE_MD_NUMBER;
        ?DNS_TYPE_MF_BSTR -> ?DNS_TYPE_MF_NUMBER;
        ?DNS_TYPE_CNAME_BSTR -> ?DNS_TYPE_CNAME_NUMBER;
        ?DNS_TYPE_SOA_BSTR -> ?DNS_TYPE_SOA_NUMBER;
        ?DNS_TYPE_MB_BSTR -> ?DNS_TYPE_MB_NUMBER;
        ?DNS_TYPE_MG_BSTR -> ?DNS_TYPE_MG_NUMBER;
        ?DNS_TYPE_MR_BSTR -> ?DNS_TYPE_MR_NUMBER;
        ?DNS_TYPE_NULL_BSTR -> ?DNS_TYPE_NULL_NUMBER;
        ?DNS_TYPE_WKS_BSTR -> ?DNS_TYPE_WKS_NUMBER;
        ?DNS_TYPE_PTR_BSTR -> ?DNS_TYPE_PTR_NUMBER;
        ?DNS_TYPE_HINFO_BSTR -> ?DNS_TYPE_HINFO_NUMBER;
        ?DNS_TYPE_MINFO_BSTR -> ?DNS_TYPE_MINFO_NUMBER;
        ?DNS_TYPE_MX_BSTR -> ?DNS_TYPE_MX_NUMBER;
        ?DNS_TYPE_TXT_BSTR -> ?DNS_TYPE_TXT_NUMBER;
        ?DNS_TYPE_RP_BSTR -> ?DNS_TYPE_RP_NUMBER;
        ?DNS_TYPE_AFSDB_BSTR -> ?DNS_TYPE_AFSDB_NUMBER;
        ?DNS_TYPE_X25_BSTR -> ?DNS_TYPE_X25_NUMBER;
        ?DNS_TYPE_ISDN_BSTR -> ?DNS_TYPE_ISDN_NUMBER;
        ?DNS_TYPE_RT_BSTR -> ?DNS_TYPE_RT_NUMBER;
        ?DNS_TYPE_NSAP_BSTR -> ?DNS_TYPE_NSAP_NUMBER;
        ?DNS_TYPE_SIG_BSTR -> ?DNS_TYPE_SIG_NUMBER;
        ?DNS_TYPE_KEY_BSTR -> ?DNS_TYPE_KEY_NUMBER;
        ?DNS_TYPE_PX_BSTR -> ?DNS_TYPE_PX_NUMBER;
        ?DNS_TYPE_GPOS_BSTR -> ?DNS_TYPE_GPOS_NUMBER;
        ?DNS_TYPE_AAAA_BSTR -> ?DNS_TYPE_AAAA_NUMBER;
        ?DNS_TYPE_LOC_BSTR -> ?DNS_TYPE_LOC_NUMBER;
        ?DNS_TYPE_NXT_BSTR -> ?DNS_TYPE_NXT_NUMBER;
        ?DNS_TYPE_EID_BSTR -> ?DNS_TYPE_EID_NUMBER;
        ?DNS_TYPE_NIMLOC_BSTR -> ?DNS_TYPE_NIMLOC_NUMBER;
        ?DNS_TYPE_SRV_BSTR -> ?DNS_TYPE_SRV_NUMBER;
        ?DNS_TYPE_ATMA_BSTR -> ?DNS_TYPE_ATMA_NUMBER;
        ?DNS_TYPE_NAPTR_BSTR -> ?DNS_TYPE_NAPTR_NUMBER;
        ?DNS_TYPE_KX_BSTR -> ?DNS_TYPE_KX_NUMBER;
        ?DNS_TYPE_CERT_BSTR -> ?DNS_TYPE_CERT_NUMBER;
        ?DNS_TYPE_DNAME_BSTR -> ?DNS_TYPE_DNAME_NUMBER;
        ?DNS_TYPE_SINK_BSTR -> ?DNS_TYPE_SINK_NUMBER;
        ?DNS_TYPE_OPT_BSTR -> ?DNS_TYPE_OPT_NUMBER;
        ?DNS_TYPE_APL_BSTR -> ?DNS_TYPE_APL_NUMBER;
        ?DNS_TYPE_DS_BSTR -> ?DNS_TYPE_DS_NUMBER;
        ?DNS_TYPE_SSHFP_BSTR -> ?DNS_TYPE_SSHFP_NUMBER;
        ?DNS_TYPE_IPSECKEY_BSTR -> ?DNS_TYPE_IPSECKEY_NUMBER;
        ?DNS_TYPE_RRSIG_BSTR -> ?DNS_TYPE_RRSIG_NUMBER;
        ?DNS_TYPE_NSEC_BSTR -> ?DNS_TYPE_NSEC_NUMBER;
        ?DNS_TYPE_DNSKEY_BSTR -> ?DNS_TYPE_DNSKEY_NUMBER;
        ?DNS_TYPE_NSEC3_BSTR -> ?DNS_TYPE_NSEC3_NUMBER;
        ?DNS_TYPE_NSEC3PARAM_BSTR -> ?DNS_TYPE_NSEC3PARAM_NUMBER;
        ?DNS_TYPE_DHCID_BSTR -> ?DNS_TYPE_DHCID_NUMBER;
        ?DNS_TYPE_HIP_BSTR -> ?DNS_TYPE_HIP_NUMBER;
        ?DNS_TYPE_NINFO_BSTR -> ?DNS_TYPE_NINFO_NUMBER;
        ?DNS_TYPE_RKEY_BSTR -> ?DNS_TYPE_RKEY_NUMBER;
        ?DNS_TYPE_TALINK_BSTR -> ?DNS_TYPE_TALINK_NUMBER;
        ?DNS_TYPE_SPF_BSTR -> ?DNS_TYPE_SPF_NUMBER;
        ?DNS_TYPE_UINFO_BSTR -> ?DNS_TYPE_UINFO_NUMBER;
        ?DNS_TYPE_UID_BSTR -> ?DNS_TYPE_UID_NUMBER;
        ?DNS_TYPE_GID_BSTR -> ?DNS_TYPE_GID_NUMBER;
        ?DNS_TYPE_UNSPEC_BSTR -> ?DNS_TYPE_UNSPEC_NUMBER;
        ?DNS_TYPE_TKEY_BSTR -> ?DNS_TYPE_TKEY_NUMBER;
        ?DNS_TYPE_TSIG_BSTR -> ?DNS_TYPE_TSIG_NUMBER;
        ?DNS_TYPE_IXFR_BSTR -> ?DNS_TYPE_IXFR_NUMBER;
        ?DNS_TYPE_AXFR_BSTR -> ?DNS_TYPE_AXFR_NUMBER;
        ?DNS_TYPE_MAILB_BSTR -> ?DNS_TYPE_MAILB_NUMBER;
        ?DNS_TYPE_MAILA_BSTR -> ?DNS_TYPE_MAILA_NUMBER;
        ?DNS_TYPE_ANY_BSTR -> ?DNS_TYPE_ANY_NUMBER;
        ?DNS_TYPE_DLV_BSTR -> ?DNS_TYPE_DLV_NUMBER;
        _ -> undefined
    end.

root_hints() ->
    {
      [
       #dns_rr{name = <<"">>, type=?DNS_TYPE_NS, ttl=518400, data = #dns_rrdata_ns{dname = <<"a.root-servers.net">>}},
       #dns_rr{name = <<"">>, type=?DNS_TYPE_NS, ttl=518400, data = #dns_rrdata_ns{dname = <<"b.root-servers.net">>}},
       #dns_rr{name = <<"">>, type=?DNS_TYPE_NS, ttl=518400, data = #dns_rrdata_ns{dname = <<"c.root-servers.net">>}},
       #dns_rr{name = <<"">>, type=?DNS_TYPE_NS, ttl=518400, data = #dns_rrdata_ns{dname = <<"d.root-servers.net">>}},
       #dns_rr{name = <<"">>, type=?DNS_TYPE_NS, ttl=518400, data = #dns_rrdata_ns{dname = <<"e.root-servers.net">>}},
       #dns_rr{name = <<"">>, type=?DNS_TYPE_NS, ttl=518400, data = #dns_rrdata_ns{dname = <<"f.root-servers.net">>}},
       #dns_rr{name = <<"">>, type=?DNS_TYPE_NS, ttl=518400, data = #dns_rrdata_ns{dname = <<"g.root-servers.net">>}},
       #dns_rr{name = <<"">>, type=?DNS_TYPE_NS, ttl=518400, data = #dns_rrdata_ns{dname = <<"h.root-servers.net">>}},
       #dns_rr{name = <<"">>, type=?DNS_TYPE_NS, ttl=518400, data = #dns_rrdata_ns{dname = <<"i.root-servers.net">>}},
       #dns_rr{name = <<"">>, type=?DNS_TYPE_NS, ttl=518400, data = #dns_rrdata_ns{dname = <<"j.root-servers.net">>}},
       #dns_rr{name = <<"">>, type=?DNS_TYPE_NS, ttl=518400, data = #dns_rrdata_ns{dname = <<"k.root-servers.net">>}},
       #dns_rr{name = <<"">>, type=?DNS_TYPE_NS, ttl=518400, data = #dns_rrdata_ns{dname = <<"l.root-servers.net">>}},
       #dns_rr{name = <<"">>, type=?DNS_TYPE_NS, ttl=518400, data = #dns_rrdata_ns{dname = <<"m.root-servers.net">>}}
      ], [
          #dns_rr{name = <<"a.root-servers.net">>, type=?DNS_TYPE_A, ttl=3600000, data = #dns_rrdata_a{ip = {198,41,0,4}}},
          #dns_rr{name = <<"b.root-servers.net">>, type=?DNS_TYPE_A, ttl=3600000, data = #dns_rrdata_a{ip = {192,228,79,201}}},
          #dns_rr{name = <<"c.root-servers.net">>, type=?DNS_TYPE_A, ttl=3600000, data = #dns_rrdata_a{ip = {192,33,4,12}}},
          #dns_rr{name = <<"d.root-servers.net">>, type=?DNS_TYPE_A, ttl=3600000, data = #dns_rrdata_a{ip = {128,8,10,90}}},
          #dns_rr{name = <<"e.root-servers.net">>, type=?DNS_TYPE_A, ttl=3600000, data = #dns_rrdata_a{ip = {192,203,230,10}}},
          #dns_rr{name = <<"f.root-servers.net">>, type=?DNS_TYPE_A, ttl=3600000, data = #dns_rrdata_a{ip = {192,5,5,241}}},
          #dns_rr{name = <<"g.root-servers.net">>, type=?DNS_TYPE_A, ttl=3600000, data = #dns_rrdata_a{ip = {192,112,36,4}}},
          #dns_rr{name = <<"h.root-servers.net">>, type=?DNS_TYPE_A, ttl=3600000, data = #dns_rrdata_a{ip = {128,63,2,53}}},
          #dns_rr{name = <<"i.root-servers.net">>, type=?DNS_TYPE_A, ttl=3600000, data = #dns_rrdata_a{ip = {192,36,148,17}}},
          #dns_rr{name = <<"j.root-servers.net">>, type=?DNS_TYPE_A, ttl=3600000, data = #dns_rrdata_a{ip = {192,58,128,30}}},
          #dns_rr{name = <<"k.root-servers.net">>, type=?DNS_TYPE_A, ttl=3600000, data = #dns_rrdata_a{ip = {193,0,14,129}}},
          #dns_rr{name = <<"l.root-servers.net">>, type=?DNS_TYPE_A, ttl=3600000, data = #dns_rrdata_a{ip = {198,32,64,12}}},
          #dns_rr{name = <<"m.root-servers.net">>, type=?DNS_TYPE_A, ttl=3600000, data = #dns_rrdata_a{ip = {202,12,27,33}}}
         ]
    }.
