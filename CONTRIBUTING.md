# Contributing to erldns

## Getting Started

### Prerequisites

- Erlang/OTP 27 or 28
- Rebar3
- Git

### Setup

1. Clone the repository:
   ```sh
   git clone git@github.com:dnsimple/erldns.git
   cd erldns
   ```

2. Install dependencies:
   ```sh
   make
   ```

   To update dependencies:
   ```sh
   rebar3 upgrade --all
   ```

## Development Workflow

### Formatting

Format code before committing:
```sh
make format
```

### Linting

Check code style:
```sh
make lint
```

### Testing

Run the full test suite:
```sh
make test
```

This runs formatting checks, linting, static analysis (xref, dialyzer), documentation generation, tests (Common Test), and coverage.

### Interactive Development

Start an Erlang shell with the application loaded:
```sh
rebar3 shell
```

## Release Process

1. Ensure all tests pass: `make test`

1. Update `CHANGELOG.md` - finalize the `## main` section with the version number

1. Use semantic versioning: vMAJOR.MINOR.PATCH:
   ```sh
   # Example
   export VERSION=v1.2.3
   ```

1. Commit and push:
   ```sh
   git commit -a -m "Release $VERSION"
   git push origin main
   ```

1. Wait for CI to complete successfully

1. Create and push a signed tag:
   ```sh
   git tag -a v$VERSION -s -m "Release $VERSION"
   git push origin --tags
   ```

1. GitHub Actions will automatically publish to [Hex.pm](https://hex.pm/packages/erldns)

## Code Standards

Follow the [Inaka Erlang Guidelines](https://github.com/inaka/erlang_guidelines) as the primary coding convention. The guidelines below supplement and emphasize project-specific patterns.

### Erlang Style

- **Pattern matching**: Prefer pattern matching and function-head dispatch over nested conditionals
  - Use `case ... of` or pattern-matching function heads instead of `if` expressions
  - Use `case {Cond1, Cond2, ...} of` for multiple conditionals where it helps instead of `if` expressions
- **Functions**: Keep functions short with single responsibilities; break complex logic into helpers
- **Traceability**: Favour named functions over anonymous ones, as naming enhances debugging

### Types & Specs

- Always provide `-spec` definitions for exported functions
- Always provide types in record definitions
- Dialyzer is required (runs in CI)

### Testing

- Common Test (ct): For unit and integration tests (strictly preferred over `eunit`), use parallel test cases when possible.

### Observability

- Prefer emitting `telemetry` events under the `erldns` list head when needed
- Emit logs with `logger` sporadically,
  - Use structured logging with contextual keys:
   - `what`: mandatory, should point to an atom with a short explanation of the issue
   - `message`: optional, if present should contain a utf8 binary with a human-friendly explanation
  - Provide the log domain in the metadata scoped to this repository (`#{domain => [erldns, ...]}`)

### Commit Messages

Use conventional, descriptive commit messages:

```
Short summary (<= 72 chars)

Detailed description explaining:
- The reason for the change
- Any side effects
- How it was tested
```

## Submitting Changes

- Format code with `make format`
- Write tests for your changes, every change should be automatically tested comprehensively
- Ensure `make test` passes locally
- Submit a PR targeting `main`, CI will run the full test suite automatically
