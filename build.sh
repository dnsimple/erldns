#!/bin/sh

rm -Rf deps
./rebar clean
./rebar get-deps
cd deps/epgsql
./rebar compile
cd ../../
./rebar compile
