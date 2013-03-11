#!/bin/sh

rm -Rf deps
./rebar clean
./rebar get-deps
./rebar compile
