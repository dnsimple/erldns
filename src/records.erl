-module(records).
-export([type_to_atom/1, type_to_string/1, class_to_string/1]).

type_to_atom(Type) ->
  case Type of
    6     -> soa;
    1     -> a;
    28    -> aaaa;
    5     -> cname;
    2     -> ns;
    16    -> txt;
    15    -> mx;
    33    -> srv;
    35    -> naptr;
    12    -> ptr;
    99    -> spf;
    44    -> sshfp;

    _     -> Type
  end.

class_to_string(Value) ->
  case Value of
    1       -> "IN";
    2       -> "CS";
    3       -> "CH";
    4       -> "HS";
    _       -> Value
  end.

type_to_string(Value) ->
  case Value of
    1       -> "A";
    28      -> "AAAA";
    18      -> "AFSDB";
    42      -> "APL";
    37      -> "CERT";
    5       -> "CNAME";
    49      -> "DHCID";
    32769   -> "DLV";
    39      -> "DNAME";
    48      -> "DNSKEY";
    43      -> "DS";
    55      -> "HIP";
    45      -> "IPSECKEY";
    25      -> "KEY";
    36      -> "KX";
    29      -> "LOC";
    15      -> "MX";
    35      -> "NAPTR";
    2       -> "NS";
    47      -> "NSEC";
    50      -> "NSEC3";
    51      -> "NSEC3PARAM";
    12      -> "PTR";
    46      -> "RRSIG";
    17      -> "RP";
    24      -> "SIG";
    6       -> "SOA";
    99      -> "SPF";
    33      -> "SRV";
    44      -> "SSHFP";
    32768   -> "TA";
    249     -> "TKEY";
    52      -> "TLSA";
    250     -> "TSIG";
    16      -> "TXT";

    %% AXFR and pseudo records
    255     -> "*";
    252     -> "AXFR";
    251     -> "IXFR";
    41      -> "OPT";

    %% Obsolete
    3       -> "MD";
    4       -> "MF";
    254     -> "MAILA";
    7       -> "MB";
    8       -> "MG";
    9       -> "MR";
    14      -> "MINFO";
    253     -> "MAILB";
    11      -> "WKS";
    10      -> "NULL";
    38      -> "A6";
    30      -> "NXT";
    13      -> "HINFO";
    19      -> "X25";
    20      -> "ISDN";
    21      -> "RT";
    22      -> "NSAP";
    23      -> "NSAP-PTR";
    26      -> "PX";
    31      -> "EID";
    32      -> "NIMLOC";
    34      -> "ATMA";
    40      -> "SINK";
    27      -> "GPOS";
    100     -> "UINFO";
    101     -> "UID";
    102     -> "GID";
    103     -> "UNSPEC";

    %% Catchall for anything else
    _       -> Value 
  end.

