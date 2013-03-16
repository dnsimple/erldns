# Erlang DNS Server

Serve DNS authoritative responses...with Erlang.

## Building

To build clean:

    ./build.sh

If you've already built once and just want to recompile the erl-dns source:

    ./rebar compile

## Zones

Zones are loaded in from JSON, either locally or through a zone server (more info coming on this).

Example JSON files are in the priv/ directory.

## Configuration

An example configuration file can be found in erldns.config.example.

Copy it to erldns.config and modify as needed.

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

## Performance

Currently this system is able to handle around 1k QPS of real traffic.

The goal is 10k QPS.
