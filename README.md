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
The system responsible for loading and caching zone data.

- `m:erldns_pipeline`
The system responsible for processing incoming DNS queries, including resolution and any extension thereof.

- `m:erldns_listeners`
The system responsible for listening for incoming DNS queries. The system is designed to be able to listen on multiple ports and interfaces and supports both UDP and TCP, Unix network stack optimisations, and high parallelism.

There is also an [Admin API](docs/admin-api.md) for querying the current zone cache and for basic control.

## Instrumentation

[Telemetry](https://hex.pm/packages/telemetry) is used to instrument the code.

All events are divided in the following namespaces:

- `[erldns, pipeline | _]` are triggered by the `m:erldns_pipeline` subsystem.
- `[erldns, request | _]` are triggered by the `m:erldns_listeners` subsystem.

## Getting started

You can use this application as a standalone service or embedded into your OTP application. In both
cases, you'll need to: configure it, and load zones.

### Zones

Zones are loaded from JSON files in the `priv/zones/` directory. The path is configured in `erldns.config` using the `zones.path` setting. For more details about zone file format and configuration, see [`priv/zones/ZONES`](priv/zones/ZONES.md).

### Configuration

An example configuration file can be found in `erldns.example.config`. For more details, see the
subsystems and the admin API documentation.

To get started, copy it into your own `erldns.config` and modify as needed.

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
rebar3 shell
```

### Build a distribution with and run the release

```sh
rebar3 release
_build/default/rel/erldns/bin/erldns foreground
```

## Usage

### DNS Queries

Here are some queries to try:

```sh
dig -p 8053 @127.0.0.1 example.com a
dig -p 8053 @127.0.0.1 example.com cname
dig -p 8053 @127.0.0.1 example.com ns
dig -p 8053 @127.0.0.1 example.com mx
dig -p 8053 @127.0.0.1 example.com txt
dig -p 8053 @127.0.0.1 example.com sshfp
dig -p 8053 @127.0.0.1 example.com soa
dig -p 8053 @127.0.0.1 example.com naptr
dig -p 8053 @127.0.0.1 -x 127.0.0.1 ptr
```

### Admin API

The Admin API provides a RESTful HTTP interface for managing zones at runtime. By default, it listens on port `8083`.

```sh
# List all zones
curl http://localhost:8083/

# Get zone details
curl http://localhost:8083/zones/example.com

# Get specific records
curl "http://localhost:8083/zones/example.com/records/example.com?type=A"
```

For complete documentation including authentication, TLS configuration, and extensibility options, see the [Admin API documentation](docs/admin-api.md).

## Performance

If you want to perform some benchmarks, see the [benchmarking guide](./BENCHMARKING.md).

## AXFR Support

AXFR zone transfers are not currently implemented. The current implementation (`m:erldns_axfr`) is a stub.

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
- [Common Tests](https://www.erlang.org/doc/apps/common_test/ct.html)
- [Coverage](https://www.erlang.org/doc/apps/tools/cover.html)
