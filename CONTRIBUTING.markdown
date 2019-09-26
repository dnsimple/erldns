# Contributing

erldns is an open source project licensed under an MIT license. Contributions are gladly accepted via GitHub pull requests.

## Testing

erldns includes several test mechanisms.

### Unit Testing & Static Analysis

To execute unit tests (and dialyzer for static analysis):

```
make test
```

### Functional Testing

The [dnstest](https://github.com/dnsimple/dnstest) tool provides a suite of black-box functional tests for erldns (and any other DNS authoritative name server). The tests are largely based on the excellent [suite of tests](https://github.com/PowerDNS/pdns/tree/master/regression-tests/tests) in [PowerDNS](http://powerdns.com). To run the tests, you must change `erldns.config` so that zones are loaded from `priv/test.zones.json`.

```
[
  {erldns, [
    {zones, "priv/test.zones.json"}
  ]}
]
```

Then you will need to run erldns. At this point it should be ready to test with dnstest. See the dnstest README for more details on how to run dnstest.
