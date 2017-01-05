all: clean build

build:
	./rebar get-deps
	./rebar compile

fresh:
	rm -Rf deps
	./rebar clean

clean:
	./rebar clean

test:
	./rebar get-deps
	./rebar eunit skip_deps=true
	./rebar3 eunit
	./rebar3 dialyzer
