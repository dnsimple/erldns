all: clean build

build:
	./rebar3 get-deps
	./rebar3 compile

fresh:
	rm -Rf _build
	./rebar3 clean

clean:
	./rebar3 clean

test:
	./rebar3 get-deps
	./rebar3 eunit
	./rebar3 dialyzer
