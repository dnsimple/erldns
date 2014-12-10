#!/bin/sh

erl -config master.config -pa ebin deps/**/ebin -s erldns -sname master
