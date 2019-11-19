-module(t).

-export([t/2] ).

t(N, F) ->
  {T, V} = timer:tc(F),
  lager:info("~s: ~p", [N, T / 1000]),
  V.
