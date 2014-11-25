all: clean-all build-all

build-all:
	./rebar get-deps
	./rebar compile

build:
	./rebar compile

get-deps:
	./rebar get-deps

clean:
	./rebar clean

clean-deps:
	rm -Rf deps

clean-all:
	rm -Rf deps
	./rebar clean


dialyzer-init:
	dialyzer --build-plt --apps erts kernel stdlib

dialyzer:
	dialyzer -r src --src

