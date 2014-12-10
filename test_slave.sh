#!/bin/sh

erl -config slave.config -pa ebin deps/**/ebin -s erldns -sname slave
