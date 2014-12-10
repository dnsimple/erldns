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
	echo "You need to have a slave running before running this test! < ./test_slave.sh >"
	echo "Make sure you have configured correct IP for (master.config, slave.config)"
	rm -f test/*beam
	./rebar compile
	ct_run -config master.config -dir test -suite master_SUITE -logdir test_logs -pa ebin deps/**/ebin/ -s erldns

test-slave:
	echo "You need to have a master running before running this test! < ./test_master.sh >"
	echo "Make sure you have configured correct IP for (master.config, slave.config)"
	rm -f test/*beam
	./rebar compile
	ct_run -config slave.config -dir test -suite slave_SUITE -logdir test_logs -pa ebin deps/**/ebin/ -s erldns

test-clean-run:
	rm -f test/*beam
	./rebar clean compile
	ct_run -dir test -suite erldns_SUITE -logdir test_logs -pa ebin/ deps/*/ebin/*

test-clean:
	rm -rf logs/*
