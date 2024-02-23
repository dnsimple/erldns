REBAR:=$(shell which rebar3 || echo ./rebar3)
REBAR_URL:="https://s3.amazonaws.com/rebar3/rebar3"

all: clean build

$(REBAR):
	curl -o rebar3 $(REBAR_URL) && chmod +x rebar3

.PHONY: build
build: $(REBAR)
	$(REBAR) compile

.PHONY: release
release: $(REBAR)
	$(REBAR) release

.PHONY: fresh
fresh: $(REBAR)
	rm -Rf _build
	$(REBAR) clean

.PHONY: clean
clean: $(REBAR)
	$(REBAR) clean

.PHONY: test
test: $(REBAR)
	$(REBAR) eunit
	$(REBAR) dialyzer
