# Erlang DNS Server

Serve DNS authoritative responses... with Erlang.

[![Build Status](https://github.com/dnsimple/erldns/actions/workflows/ci.yml/badge.svg)](https://github.com/dnsimple/erldns/actions/workflows/ci.yml)
[![Module Version](https://img.shields.io/hexpm/v/erldns.svg)](https://hex.pm/packages/erldns)

## Requirements

Erlang/OTP 27+

## Building

To build:

```shell
make
```

To start fresh:

```shell
make fresh
make
```

## Zones

Zones are loaded from JSON. Example JSON files are in the `priv/` directory.

You can also write new systems to load zones by writing the zones directly to the zone cache using `erldns_zone_cache:put_zone/1`.

## Configuration

An example configuration file can be found in `erldns.example.config`. Copy it to `erldns.config` and modify as needed.

## Running

### Launch directly

```shell
overmind start
```

### To get an interactive Erlang REPL

```shell
./rebar3 shell
```

### Build a distribution with and run the release

```shell
./rebar3 release
./_build/default/rel/erldns/bin/erldns foreground
```

## Querying

Here are some queries to try:

```bash
dig -p 8053 @127.0.0.1 example.com a
dig -p 8053 @127.0.0.1 example.com cname
dig -p 8053 @127.0.0.1 example.com ns
dig -p 8053 @127.0.0.1 example.com mx
dig -p 8053 @127.0.0.1 example.com spf
dig -p 8053 @127.0.0.1 example.com txt
dig -p 8053 @127.0.0.1 example.com sshfp
dig -p 8053 @127.0.0.1 example.com soa
dig -p 8053 @127.0.0.1 example.com naptr

dig -p 8053 @127.0.0.1 -x 127.0.0.1 ptr
```

## Performance

In our environment (DNSimple) we are seeing 30 to 65 µs handoff times to retrieve a packet from the UDP port and give it to a worker for processing. Your performance may vary, but given those measurements erl-dns is capable of handling between 15k and 30k questions per second. Please note: You may need to configure the number of workers available to handle traffic at higher volumes.

If you want to perform some benchmarks, see [`BENCHMARKING.md`](./BENCHMARKING.md).

## Design

The `erldns_resolver` module will attempt to find zone data in the zone cache. If you're embedding erl-dns in your application the easiest thing to do is to load the zone cache once the zone cache `gen_server` starts push an updated zone into the cache each time data changes.

To insert a zone, use `erldns_zone_cache:put_zone({Name, Records})` where Name is a binary term such as <<"example.com">> and Records is a list of `dns_rr` records (whose definitions can be found in `deps/dns/include/dns_records.hrl`). The name of each record must be the fully qualified domain name (including the zone part).

Here's an example:

```erlang
erldns_zone_cache:put_zone({
  <<"example.com">>, [
    #dns_rr{
      name = <<"example.com">>,
      type = ?DNS_TYPE_A,
      ttl = 3600,
      data = #dns_rrdata_a{ip = {1,2,3,4}}
    },
    #dns_rr{
      name = <<"www.example.com">>,
      type = ?DNS_TYPE_CNAME,
      ttl = 3600,
      data = #dns_rrdata_cname{dname = <<"example.com">>}
    }
  ]}).
```

### AXFR Support

AXFR zone transfers are not currently implemented. The current "implementation" is just a stub.

## Instrumentation

[Telemetry](https://hex.pm/packages/telemetry) is used to instrument the code.

## Admin

There is an administrative API for querying the current zone cache and for basic control.
You can read more about it at `m:erldns_admin`.

## Tests

To run automated tests:

```shell
make test
```

This runs both [EUnit](https://www.erlang.org/doc/apps/eunit/chapter.html) tests and [dialyzer](https://www.erlang.org/docs/23/man/dialyzer.html).
