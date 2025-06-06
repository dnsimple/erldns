# Benchmarking

This guide contains some information on how to benchmark `erldns` locally.

## Install `dnsperf`

The recommended benchmarking tool is [`dnsperf`](https://github.com/DNS-OARC/dnsperf). You can compile it from source or, if on macOS, install it with:

```shell
brew install dnsperf
```

## Create a Queries File

`dnsperf` requires DNS queries to run in order to perform benchmarks. You can use whatever queries to test different aspects of `erldns`, such as how it behaves when mostly responding to unknown records or when you execute the same query many times in a row.

A good start is a small file with some `example.com`-related queries, as `example.com` domains are the default in [the sample config file](./erldns.example.config).

Put this in `queries.txt`:

```text
thumbs2.ebaystatic.com. AAAA
sip.hotmail.com. A
google.com. A
cache.defamer.com. A
example.com. A
www.example.com. CNAME
```

## Start the Server

> ### Important {: .tip}
>
> Start `erldns` as a release to make sure it gets compiled with production-like settings, rather than dev settings (as in `rebar3 shell`).

First, create a release:

```shell
rebar3 release
```

Then, start the release in the foreground:

```shell
./_build/default/rel/erldns/bin/erldns foreground
```

## Run the Benchmark

Now you're ready to run benchmarks. For example:

```shell
dnsperf -p 8053 -d ./queries.txt -T 4 -c 20 -n 10000
```

See `dnsperf -h` for an explanation of the flags.

### Latest Benchmark

The latest benchmark was run on 2024/10/06 by @nelsonvides, on an 2023 Apple MacBook Pro, 16-inch, M3 Pro CPU, 36GB of memory.

In these conditions, `erldns` can serve around 68k queries per second. The details of the benchmark are below.

#### Input queries file

```text
thumbs2.ebaystatic.com. AAAA
sip.hotmail.com. A
google.com. A
cache.defamer.com. A
example.com. A
www.example.com. CNAME
```

#### Command

```shell
dnsperf -p 8053 -d ./queries.txt -T 6 -c 256 -l 30
```

#### Results

```text
DNS Performance Testing Tool
Version 2.14.0

[Status] Command line: dnsperf -p 8053 -d ./queries.txt -T 6 -c 256 -l 30
[Status] Sending queries (to 127.0.0.1:8888)
[Status] Started at: Sun Mar 30 09:02:25 2025
[Status] Stopping after 30.000000 seconds
[Status] Testing complete (time limit)

Statistics:

  Queries sent:         2048492
  Queries completed:    2048492 (100.00%)
  Queries lost:         0 (0.00%)

  Response codes:       NOERROR 2048492 (100.00%)
  Average packet size:  request 48, response 64
  Run time (s):         30.001079
  Queries per second:   68280.610841

  Average Latency (s):  0.001239 (min 0.000055, max 0.021753)
  Latency StdDev (s):   0.000768
```
