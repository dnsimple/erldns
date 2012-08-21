# Erlang DNS Server

Serve DNS authoritative responses...with Erlang.

## Building

In one call:

    make

Or two:

    ./rebar get-deps
    ./rebar compile

## Database

Currently the MySQL responder uses the PowerDNS schema. See "http://doc.powerdns.com/generic-mypgsql-backends.html#idp8855424":http://doc.powerdns.com/generic-mypgsql-backends.html#idp8855424

## Running

Launch directly:

    erl -config erldns.config -pa ./ebin ./deps/lager/ebin ./deps/mysql/ebin ./deps/poolboy/ebin ./deps/dns/ebin -s erldns

Or use Foreman:

    foreman start

## Querying

Here are some queries to try:

    dig -p8053 @127.0.0.1 example.com a
    dig -p8053 @127.0.0.1 example.com cname
    dig -p8053 @127.0.0.1 example.com ns
    dig -p8053 @127.0.0.1 example.com mx
    dig -p8053 @127.0.0.1 example.com spf
    dig -p8053 @127.0.0.1 example.com txt
    dig -p8053 @127.0.0.1 example.com sshfp
    dig -p8053 @127.0.0.1 example.com soa
    dig -p8053 @127.0.0.1 example.com naptr

    dig -p8053 @127.0.0.1 -x 127.0.0.1 ptr

