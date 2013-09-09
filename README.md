# Erlang DNS Server

Serve DNS authoritative responses...with Erlang.

[![Build Status](https://travis-ci.org/aetrion/erl-dns.png?branch=master)](https://travis-ci.org/aetrion/erl-dns)

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

## Design

The erldns_resolver module will attempt to find zone data in the zone cache. If you're embedding erl-dns in your application the easiest thing to do is to load the zone cache once the zone cache gen_server starts push an updated zone into the cache each time data changes.

To insert a zone, use erldns_zone_cache:put_zone({Name, Records}) where Name is a binary term such as <<"example.com">> and Records is a list of dns_rr records (whose definitions can be found in deps/dns/include/dns_records.hrl). The name of each record must be the fully qualified domain name (including the zone part).

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

## Metrics

Folsom is used to gather runtime metrics and statistics. There is an HTTP server included that produces a JSON report containing these metrics. Here's an example script that shows how to get the output with curl and pass through Python to format it in a pretty fashion.

```sh
curl -s http://localhost:8082/ -H "Accept: application/json" | python -mjson.tool
```
