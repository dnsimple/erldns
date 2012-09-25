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

    erl -config erldns.config -pa ebin -pa deps/**/ebin -s erldns

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

## Custom Responders

Responders follow a simple API of the following functions:

* answer/2. The arguments passed in are Qname and Qtype.
* get_soa/1. The argument is Qname.
* get_metadata/1. The argument is Qname.

To implement your own responder:

* Implement the answer/2, get_soa/1 and get_metadata/1 functions and export them.
* Add your module name to the responders list in erldns.config.

The erldns_mysql_responder is an example of how to write a responder.

