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
	rebar3 fmt --check
	rebar3 xref
	rebar3 dialyzer
	rebar3 ex_doc
	rebar3 eunit
	rebar3 ct
	rebar3 do cover, covertool generate

.PHONY: format
format:
	rebar3 fmt
