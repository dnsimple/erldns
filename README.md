# Erlang DNS Server

Serve DNS authoritative responses... with Erlang.

[![CI](https://github.com/dnsimple/erldns/actions/workflows/ci.yml/badge.svg)](https://github.com/dnsimple/erldns/actions/workflows/ci.yml)

## Building

To build:

```
make
```

To start fresh:

```
make fresh
make
```

## Zones

Zones are loaded from JSON. Example JSON files are in the `priv/` directory.

You can also write new systems to load zones by writing the zones directly to the zone cache using `erldns_zone_cache:put_zone/1`.

## Configuration

An example configuration file can be found in `erldns.example.config`. Copy it to `erldns.config` and modify as needed.

## Running

### Launch directly:

```bash
overmind start
```

### To get an interactive Erlang REPL:

```bash
./rebar3 shell
```

### Build a distribution with and run the release:

```bash
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

## Metrics

Folsom is used to gather runtime metrics and statistics.

There is an HTTP API for querying metric data available at <https://github.com/dnsimple/erldns-metrics>

## Tracing

This project uses [OpenTelemetry](https://opentelemetry.io/docs/erlang/) (OTEL) Tracing to provide telemetry data on request processing inside of **erldns**.

To enable opentelmetry tracing, you need to:

1. Add [opentelemetry](https://github.com/open-telemetry/opentelemetry-erlang#including-in-release) as dependency of your application.
2. Configure the opentelemetry client:

   Add the following configuration to the [erldns.config](erldns.config.example):

   ```erlang
     {opentelemetry,[
       {processors,
           [{otel_batch_processor,
               #{exporter => {opentelemetry_exporter, #{protocol => http_protobuf,
                                                       endpoints => [{http, "127.0.0.1", 55681, []}]}}}}]}
     ]}
   ```

  NOTE: You will need to have a running [OpenTelemetry Collector](https://github.com/open-telemetry/opentelemetry-collector-contrib).

Application traces:

| Name                       | Dimensions                                                                                                |
| -------------------------- | --------------------------------------------------------------------------------------------------------- |
| erldns_tcp_worker          |                                                                                                           |
| handle_tcp_dns_query       | status, qr, rd, ad, qname, qtype                                                                          |
| handle_decoded_tcp_message | status                                                                                                    |
| send_tcp_message           |                                                                                                           |
| erldns_udp_worker          | host, port, erlang_port_count, erlang_proc_count, erlang_run_queue, erlang_proc_message_queue_len, status |
| handle_udp_dns_query       | status, qr, rd, ad, qname, qtype                                                                          |
| handle_decoded_udp_message | status                                                                                                    |
| synthesize_answer          |                                                                                                           |
| encode_message             | rcode, aa, ra, answers                                                                                    |

## Admin

There is an administrative API for querying the current zone cache and for basic control. You can find it in <https://github.com/dnsimple/erldns-admin>.

## Tests

To run automated tests:

```bash
make test
```

This runs both [EUnit](https://www.erlang.org/doc/apps/eunit/chapter.html) tests and [dialyzer](https://www.erlang.org/docs/23/man/dialyzer.html).
