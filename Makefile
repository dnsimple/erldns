REBAR:=$(shell which rebar3 || echo ./rebar3)
REBAR_URL:="https://s3.amazonaws.com/rebar3/rebar3"

all: clean build

$(REBAR):
	wget $(REBAR_URL) && chmod +x rebar3

build: $(REBAR)
	$(REBAR) compile

release: $(REBAR)
	$(REBAR) release

fresh: $(REBAR)
	rm -Rf _build
	$(REBAR) clean

clean: $(REBAR)
	$(REBAR) clean

test: $(REBAR)
	$(REBAR) eunit
	$(REBAR) dialyzer
