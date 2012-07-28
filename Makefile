.PHONY: deps

all: deps
	./rebar compile

deps:
	@./rebar get-deps

clean:
	./rebar clean
