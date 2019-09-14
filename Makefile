REBAR:=$(shell which rebar3 || echo ./rebar3)
REBAR_URL:="https://s3.amazonaws.com/rebar3/rebar3"

all: clean build

$(REBAR):
	wget $(REBAR_URL) && chmod +x rebar3

build: $(REBAR)
	$(REBAR) get-deps
	$(REBAR) compile

fresh: $(REBAR)
	rm -Rf _build
	$(REBAR) clean

clean: $(REBAR)
	$(REBAR) clean

test: $(REBAR)
	$(REBAR) get-deps
	$(REBAR) eunit
	$(REBAR) dialyzer
