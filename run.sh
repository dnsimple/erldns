#!/bin/sh

erl -pa ./ebin ./deps/mysql/ebin ./deps/poolboy/ebin ./deps/dns/ebin -s erldns_server
