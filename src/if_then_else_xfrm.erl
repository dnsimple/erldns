-module(if_then_else_xfrm).

-export([parse_transform/2]).



parse_transform(Forms, _Options) ->
    parse_trans:plain_transform(fun do_transform/1, Forms).

do_transform({call, _L1,  {atom, _L2, if_then_else}, [{atom, _L3, false}, _, Else]}) ->
    [NewElse] = parse_trans:plain_transform(fun do_transform/1, [Else]),
    NewElse;
do_transform({call, _L1,  {atom, _L2, if_then_else}, [{atom, _L3, true}, Then, _Else]}) ->
    [NewThen] = parse_trans:plain_transform(fun do_transform/1, [Then]),
    NewThen;
do_transform(_Form) ->
    continue.

