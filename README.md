# Erlang DNS Server

Serve DNS authoritative responses... with Erlang.

[![Erlang/OTP Versions](https://img.shields.io/badge/erlang%2Fotp-27%7C28-blue)](https://www.erlang.org)
[![Build Status](https://github.com/dnsimple/erldns/actions/workflows/ci.yml/badge.svg)](https://github.com/dnsimple/erldns/actions/workflows/ci.yml)
[![Module Version](https://img.shields.io/hexpm/v/erldns.svg)](https://hex.pm/packages/erldns)
[![Hex Docs](https://img.shields.io/badge/hex-docs-lightgreen.svg)](https://hexdocs.pm/erldns/)
[![Hex Downloads](https://img.shields.io/hexpm/dt/erldns.svg)](https://hex.pm/packages/erldns)
[![Coverage Status](https://coveralls.io/repos/github/dnsimple/erldns/badge.svg?branch=main)](https://coveralls.io/github/dnsimple/erldns?branch=main)

This application consists of three main subsystems:

- `m:erldns_zones`
The system responsible for loading and caching zone data. Zones are loaded from JSON, example files are in the `priv/` directory. You can also write new systems to load zones by writing the zones directly to the zone cache using `erldns_zone_cache:put_zone/1`.

- `m:erldns_pipeline`
The system responsible for processing incoming DNS queries. It declares a pipeline of sequential transformations to apply to the incoming query until a response is constructed.

- `m:erldns_listeners`
The system responsible for listening for incoming DNS queries. The system is designed to be able to listen on multiple ports and interfaces and supports both UDP and TCP, Unix network stack optimisations, and high parallelism.

There is also an administrative API for querying the current zone cache and for basic control.
You can read more about it at `m:erldns_admin`.

## Instrumentation

[Telemetry](https://hex.pm/packages/telemetry) is used to instrument the code.

## Configuration

An example configuration file can be found in `erldns.example.config`.

## Building

To build:

```sh
make
```

To start fresh:

```sh
make fresh
make
```

## Running

### Launch directly

```sh
overmind start
```

### To get an interactive Erlang REPL

```sh
rebar3 sh
```

### Build a distribution with and run the release

```sh
rebar3 release
_build/default/rel/erldns/bin/erldns foreground
```

## Querying

Here are some queries to try:

```sh
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

If you want to perform some benchmarks, see [`benchmarking`](./BENCHMARKING.md).

### AXFR Support

AXFR zone transfers are not currently implemented. The current "implementation" is just a stub.

## Tests

To run automated tests:

```sh
make test
```

This runs the following:

- [erlfmt](https://hex.pm/packages/erlfmt)
- [Elvis linter](https://hex.pm/packages/elvis_core)
- [xref](https://www.erlang.org/doc/apps/tools/xref.html)
- [dialyzer](https://www.erlang.org/doc/apps/dialyzer/dialyzer.html)
- [ExDoc](https://hexdocs.pm/ex_doc/readme.html)
- [EUnit](https://www.erlang.org/doc/apps/eunit/chapter.html)
- [Common Tests](https://www.erlang.org/doc/apps/common_test/ct.html)
- [Coverage](https://www.erlang.org/doc/apps/tools/cover.html)
