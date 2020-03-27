# Contributing to DNSimple/erldns

erldns is an open source project licensed under an MIT license. Contributions are gladly accepted via GitHub pull requests.

## Getting started

#### 1. Clone the repository

Clone the repository and move into it:

```shell
git clone git@github.com:dnsimple/erldns.git
cd erldns
```

#### 2. Install Erlang

#### 3. Create your own working branch

```shell
git checkout -b dev_new_feature_xyz
```

#### 4. Build and test

Compile the project and [run the test suite](#testing) to check everything works as expected.

```shell
make all
```

#### 5. Adding local (checkout) dependencies for rebar3

Please follow the instructions available at
https://www.rebar3.org/docs/dependencies


```shell
mkdir _checkouts
ln -s ../<projectX dependency dir> _checkouts/
ln -s ../<projectY dependency dir> _checkouts/
```

## Handlers' versioning

As of 1.1.0 release, the custom handlers' implementation has been extended to
support versioning. register_handler/3 and get_versioned_handlers/0 functions 
have been added. Using versioning in new handlers is encouraged.

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

## Releasing

1. Run the test suite and ensure all the tests pass.

2. Commit and push the changes

    ```shell
    git commit -a -m "* <adding feature/enhancement X/Y/Z"
    git push origin dev_new_feature_xyz
    ```

3. Initiate PR for reviewing and merging upstream.

## Tests

Submit unit tests for your changes. You can test your changes on your machine by [running the test suite](#testing).
