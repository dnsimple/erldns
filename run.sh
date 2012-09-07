#!/bin/sh

erl -config erldns.config -pa ebin deps/**/ebin -s erldns
