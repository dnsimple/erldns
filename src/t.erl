-module(t).

-include_lib("kernel/include/logger.hrl").

-export([t/2] ).

t(N, F) ->
  {T, V} = timer:tc(F),
  ?LOG_INFO("~s: ~p", [N, T / 1000]),
  V.
