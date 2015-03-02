all: build

deps:
	./rebar get-deps

build: deps
	./rebar compile

fresh: cleandeps build

cleanbuild: clean build

cleandeps:
	rm -Rf deps

clean:
	./rebar clean

test:
	./rebar eunit skip_deps=true
