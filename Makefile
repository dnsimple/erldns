all: fresh build

build:
	./rebar get-deps
	./rebar compile

cleanbuild: clean build

fresh:
	rm -Rf deps

clean:
	./rebar clean

test:
	./rebar eunit skip_deps=true
