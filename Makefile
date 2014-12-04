all: clean build

build:	
	./rebar get-deps
	./rebar compile

clean:
	rm -Rf deps
	./rebar clean

test:
	./rebar eunit skip_deps=true
