all: clean build

.PHONY: build
build:
	rebar3 compile

.PHONY: release
release:
	rebar3 release

.PHONY: fresh
fresh:
	rm -Rf _build
	rebar3 clean

.PHONY: clean
clean:
	rebar3 clean

.PHONY: test
test:
	rebar3 eunit
	rebar3 fmt --check
	rebar3 dialyzer

.PHONY: format
format:
	rebar3 fmt
