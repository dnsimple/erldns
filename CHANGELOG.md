# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## main

## v9.0.0-rc2

### Changed

- Logic for handling DS type queries is changed to be RFC compliant, see: [#285](https://github.com/dnsimple/erldns/pull/285).

## v9.0.0-rc1

### Removed

- Support for encoding/decoding records of type SPF.

## v8.1.0

### Changed

- Add ENT support for wildcard synthesis meeting RFC 4592 specification requirements ([#279](https://github.com/dnsimple/erldns/pull/279)).
  The behaviour is currently opt-in using the `rfc_compliant_ent` option in _erdns.zones_ config.

## v8.0.0

This release has many optimisations, documentation and code quality improvements.

### Changed

- Rework `erldns_zone_cache` and `erldns_resolver`: algorithm is extensively optimised and now supports ENT correctly.
- Rework `erldns_handler`: behaviour is now improved and clearly defined. Minimum supported handler version is now `2`.
- Split `erldns_resolver` pipe into more granular steps, adding `erldns_resolver_recursive`,
  `erldns_dnssec`, `erldns_sorter`, and `erldns_section_counter`.
- Add `erldns_questions` questions filter to the packet pipeline.
- Update dns_erlang to [v4.3](https://github.com/dnsimple/dns_erlang/releases/tag/v4.3.0) and remove `erldns_records:name_type/1`.
- Accept no SOA record if no RRSIG are required.
- Documentation improvements ([#267](https://github.com/dnsimple/erldns/pull/267))
- Separate edns payload size over UDP as a configurable pipe ([#267](https://github.com/dnsimple/erldns/pull/267))
- Extend pipelines with halt and secondary pipelines ([#268](https://github.com/dnsimple/erldns/pull/268))

### Added

- `[erldns, pipeline, questions]` telemetry event with `#{count => non_neg_integer()}` where `count` is the number of questions removed.
- Document some design decisions ([#265](https://github.com/dnsimple/erldns/pull/265))
- Add TLSA record support ([#270](https://github.com/dnsimple/erldns/pull/270))

### Deprecated

- SPF record support will be removed in the upcoming releases (<https://blog.dnsimple.com/2025/07/discontinuing-spf-record-type/>)

### Fixed

- Stop overwriting SOA RRSIG TTLs ([#264](https://github.com/dnsimple/erldns/pull/264))
- Fix bug with SOA records not updating correctly ([#266](https://github.com/dnsimple/erldns/pull/266))

## v7.0.0

This is a big release full of massive performance improvements and protocol compliance,
but also of breaking changes. Read carefully the changelog and the documentation before migrating.

### Changed

The application is now divided in three core subsystems, that is, _listeners_, _packet pipelines_,
and _zones_, which are configured differently and will require migration.
See `m:erldns_listeners`. `m:erldns_pipeline` and `m:erldns_zones` respectively for documentation
on how to reconfigure.

Telemetry events, as well as logger events, are entirely scoped within these respective subsystems,
that means, that the events are now prefixed with `[erldns, request, _]`, for listener workers,
and `[erldns, pipeline]` for pipeline processing. Similarly, logger events are tagged with
`domain => [erldns, admin | listeners | pipeline | zones]` metadata, and all are structured.

#### Custom parsers and encoders

If you had any custom parser or encoder, you will need to update them to the new API, which unifies
both into a single module. See `m:erldns_zone_codec` for more information on its callbacks. Note
that the `zone_to_erlang/1,2` callbacks are now `decode/1` and `zone_*/x` callbacks are now
`encode/2`, and they all take only maps as input and output respectively.

#### TXT and SPF record formats

TXT and SPF record formats have changed, from a single string, to an array, to support
more complex DNS records & use cases, so that the following:

```json
{
  ...
  "type": "TXT",
  "data": {
    "txt": "\"Hi, this is some text\" \"with extras\""
  }
},
```

becomes

```json
{
  ...
  "type": "TXT",
  "data": {
    "txts": ["Hi, this is some text", "with extras"]
  }
},
```

A warning will be logged for each invalid record, but they will be skipped, and not loaded.

For more important changes, see:

- Refactor the query processing pipeline [#224](https://github.com/dnsimple/erldns/pull/224)
- Reimplement the network stack [#225](https://github.com/dnsimple/erldns/pull/225)
- Rework zones loader [#230](https://github.com/dnsimple/erldns/pull/230)
- Rework zones codecs [#231](https://github.com/dnsimple/erldns/pull/231)
- Rework zones cache [#232](https://github.com/dnsimple/erldns/pull/232)
- Rework documentation and internals [#233](https://github.com/dnsimple/erldns/pull/233)
- Fix overriding packet size in optrr record [#242](https://github.com/dnsimple/erldns/pull/242)
- Upgrade `dns_erlang` to v4.
- Use `segmented_cache` for the zone cache and the throttle modules.

### Added

- Support for OTP28 [#220](https://github.com/dnsimple/erldns/pull/220)
- Support for `dns_erlang` v4, which enforces strings as binaries and options as maps
- Introduce domain tag in logger events [#244](https://github.com/dnsimple/erldns/pull/244)
- zone cache `put_rrset_zone` accepts zone records [#243](https://github.com/dnsimple/erldns/pull/243)
- Add statistic functionality to listeners [#227](https://github.com/dnsimple/erldns/pull/227)

### Removed

- Support for TXT and SPF records with data as a single string, they must be a list of strings instead.
- Support for the `erldns_txt` parser [#248](https://github.com/dnsimple/erldns/pull/248)
- Support for zone parsers taking input as lists [#231](https://github.com/dnsimple/erldns/pull/231)

### Fixed

- Fix DNSSEC timestamps [#234](https://github.com/dnsimple/erldns/pull/234)
- Fix (C)DNS/(C)DNSKEY signing [#235](https://github.com/dnsimple/erldns/pull/235)
- Fix cache non-normalised match bug [#241](https://github.com/dnsimple/erldns/pull/241)

### Security

- Introduce backpressure and load shedding [#240](https://github.com/dnsimple/erldns/pull/240)

## 6.0.2

- Add mailbox length telemetry events.
- Keep the handlers state in an ets table and avoid the singleton gen_server call.

## 6.0.1

- Add terminating context to telemetry span events

## 6.0.0

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
