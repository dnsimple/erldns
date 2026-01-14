# Agent Instructions

Instructions for AI coding agents working on this Erlang DNS server project.

## Project Overview

`erldns` is an authoritative DNS nameserver written in Erlang.

## Key Documentation

- **[README.md](./README.md)** - Library overview, features, usage examples, and API reference
- **[CONTRIBUTING.md](./CONTRIBUTING.md)** - Contribution guidelines, commit format, testing approach
- **[Hex Documentation](https://hexdocs.pm/erldns/)** - API reference

## Project Structure

Main subsystems:
- `erldns_zones` - Zone loading and caching
- `erldns_pipeline` - DNS query processing pipeline
- `erldns_listeners` - UDP/TCP/TLS listeners for DNS queries
- `erldns_admin` - Administrative API

## Development Commands

- `rebar3 compile` / `make build` - Build
- `rebar3 fmt` / `make format` - Format code
- `rebar3 lint` / `make lint` - Lint code
- `make test` - Full test suite (fmt check, lint, xref, dialyzer, ex_doc, ct, cover)
- `rebar3 shell` - Interactive Erlang shell
- `rebar3 ct` - Common Test (unit/integration/system tests)
- `rebar3 xref` - Cross-reference analysis
- `rebar3 dialyzer` - Static type analysis

## Coding Standards

Follow the coding standards defined in [CONTRIBUTING.md](./CONTRIBUTING.md#code-standards), which reference the [Inaka Erlang Guidelines](https://github.com/inaka/erlang_guidelines).

## CI Requirements

Every PR must pass `make test`, which will be checked in CI

## Code Review Checklist

When reviewing or writing code:

- [ ] Code compiles: `rebar3 compile`
- [ ] Formatting correct: `rebar3 fmt --check` – fix with `rebar3 fmt`
- [ ] Tests added/updated for behavior changes
- [ ] Types and specs updated for public API changes
- [ ] Commit messages follow conventional format (see below)
- [ ] Changelog updated for user-facing changes

## Commit Messages

- Follow commit message conventions defined in [CONTRIBUTING.md](./CONTRIBUTING.md#commit-messages).
- Do not include AI attribution in commit messages or code comments

## Branching & Releases

- Branch naming: `feat/*`, `fix/*`, `chore/*`
- See [CONTRIBUTING.md](./CONTRIBUTING.md) for release process

## Project-Specific Notes

- Configuration: `erldns.example.config`
- Zone files are JSON format in `priv/zones/` (see `priv/zones/ZONES.md`)
- Default DNS port: 8053 (UDP/TCP)
- AXFR zone transfers: Not implemented (stub only)
- Minimum OTP version: 27
- Coverage requirement: 85% minimum and should only grow
