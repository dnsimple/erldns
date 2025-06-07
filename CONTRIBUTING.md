# Contributing to erldns

## Getting started

### 1. Clone the repository

Clone the repository and move into it:

```shell
git clone git@github.com:dnsimple/erldns.git
cd erldns
```

### 2. Install Erlang

### 3. Install the dependencies

```shell
make
```

#### Updating Dependencies

When dependencies are updated the rebar.lock file will need to be updated for the new dependency to be used. The following command does this:

```shell
rebar3 upgrade --all
```

## Formatting

If your editor doesn't automatically format Erlang code using [erlfmt](https://github.com/WhatsApp/erlfmt), run:

```shell
make format
```

You should run this command before releasing.

### 3. Build and test

Compile the project and [run the test suite](#testing) to check everything works as expected.

## Testing

```shell
make test
```

## Releasing

The following instructions uses `$VERSION` as a placeholder, where `$VERSION` is a `MAJOR.MINOR.BUGFIX` release such as `1.2.0`.

1. Run the test suite and ensure all the tests pass.

1. Finalize the `## main` section in `CHANGELOG.md` assigning the version.

1. Commit and push the changes

    ```shell
    git commit -a -m "Release $VERSION"
    git push origin main
    ```

1. Wait for CI to complete.

1. Create a signed tag.

    ```shell
    git tag -a v$VERSION -s -m "Release $VERSION"
    git push origin --tags
    ```

1. GitHub actions will take it from there and release to <https://hex.pm/packages/erldns>

## Tests

Submit unit tests for your changes. You can test your changes on your machine by [running the test suite](#testing).

When you submit a PR, tests will also be run on the [continuous integration environment via GitHub Actions](https://github.com/dnsimple/erldns/actions/workflows/ci.yml).
