# Erlang DNS Server

Serve DNS authoritative responses...with Erlang.

## Building

In one call:

    make

Or two:

    ./rebar get-deps
    ./rebar compile

## Running

Right now just launch the erldns_server directly.

    erl -pa ./ebin -s erldns_server

I'm working on an OTP version.

## Querying

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

