# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## main

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
