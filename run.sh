#!/bin/sh

erl -config erldns.config -pa ./ebin ./deps/lager/ebin ./deps/mysql/ebin ./deps/poolboy/ebin ./deps/dns/ebin -s erldns
