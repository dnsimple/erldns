# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## main

- Instrument code using telemetry in a metrics agnostic way.

## 5.0.0

- Introduce support for Logger
- Remove lager
- Remove the `erldns_events` singleton.

## 4.3.1

- Export dnssec internal new API endpoint

## 4.3.0

- Add support for NSEC compact denial of existence

## 4.2.4

- Add support for zone records directory loading
- Add the latest `dnstest` version fixing almost all tests

## 4.2.3

- Update `dns_erlang`: fix EDNS0 compliance for truncated records and unsupported versions

## 4.2.2

- Test admin API and fix bugs related to authentication and json encoding

## 4.2.1

- Ensure supervision tree starts correctly

## 4.2.0

- Merge admin and metrics APIs into this repository.

## 4.1.2

- Hide SPF/TXT multipart handling behind a feature flag
- Fix a bug mixing SPF and TXT records

## 4.1.1

- Bugfix handling null in the zone parser json payloads

## 4.1.0

- Introduce SPF/TXT multipart handling (#150)

## 4.0.0

- Add ex_doc support
- Remove support for OpenTelemetry.

## 3.0.0

### Changed

- Bumps to OTP/27
- Replaced "jsx" with "json"
- Bumps to [dns_erlang/v2.0.0](https://hex.pm/packages/dns_erlang/2.0.0)

### Added

- erlfmt
- CONTRIBUTING.md
- CHANGELOG.md
- release process to hex.pm

## 2.2.0

- ...
