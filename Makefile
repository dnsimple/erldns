all: clean build

build:	
	./rebar get-deps
	./rebar compile

clean:
	rm -Rf deps
	./rebar clean
