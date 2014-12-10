.PHONY: all test clean

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

test:
	rm -f test/*beam
	./rebar compile
	ct_run -config erldns.config -dir test -suite erldns_SUITE -logdir test_logs -pa ebin deps/**/ebin/ -s erldns

test-master:
	rm -f test/*beam
	./rebar compile
	ct_run -config master.config -dir test -suite master_SUITE -logdir test_logs -pa ebin deps/**/ebin/ -s erldns

test-slave:
	rm -f test/*beam
	./rebar compile
	ct_run -config slave.config -dir test -suite slave_SUITE -logdir test_logs -pa ebin deps/**/ebin/ -s erldns

test-clean-run:
	rm -f test/*beam
	./rebar clean compile
	ct_run -dir test -suite erldns_SUITE -logdir test_logs -pa ebin/ deps/*/ebin/*

test-clean:
	rm -rf logs/*
