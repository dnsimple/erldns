-module(erldns_txt).

-include("erldns.hrl").

-export([parse/1]).

-define(MAX_TXT_SIZE, 255).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

% Public API
parse(Binary) when is_binary(Binary) -> parse(binary_to_list(Binary));
parse([]) -> [];
parse([C|Rest]) -> parse_char([C|Rest], C, Rest, [], false).


parse(String, [], [], _) -> [split(String)];
parse(_, [], Tokens, _) -> Tokens;
parse(String, [C|Rest], Tokens, Escaped) -> parse_char(String, C, Rest, Tokens, Escaped).
parse(_, [], Tokens, CurrentToken, true) -> Tokens ++ [CurrentToken]; % Last character is escaped
parse(String, [C|Rest], Tokens, CurrentToken, Escaped) -> parse_char(String, C, Rest, Tokens, CurrentToken, Escaped).

parse_char(String, $", Rest, Tokens, _) -> parse(String, Rest, Tokens, [], false);
parse_char(String, _, Rest, Tokens, _) -> parse(String, Rest, Tokens, false).
parse_char(String, $", Rest, Tokens, CurrentToken, false) -> parse(String, Rest, Tokens ++ [split(CurrentToken)], false);
parse_char(String, $", Rest, Tokens, CurrentToken, true) -> parse(String, Rest, Tokens, CurrentToken ++ [$"], false);
parse_char(String, $\\, Rest, Tokens, CurrentToken, false) -> parse(String, Rest, Tokens, CurrentToken, true);
parse_char(String, $\\, Rest, Tokens, CurrentToken, true) -> parse(String, Rest, Tokens, CurrentToken ++ [$\\], false);
parse_char(String, C, Rest, Tokens, CurrentToken, _) -> parse(String, Rest, Tokens, CurrentToken ++ [C], false).

split(Data) -> split(Data, []).
split(Data, Parts) ->
  case byte_size(list_to_binary(Data)) > ?MAX_TXT_SIZE of
    true ->
      First = list_to_binary(string:substr(Data, 1, ?MAX_TXT_SIZE)),
      Rest = string:substr(Data, ?MAX_TXT_SIZE + 1),
      case Rest of
        [] -> Parts ++ [First];
        _ -> split(Rest, Parts ++ [First])
      end;
    false ->
      Parts ++ [list_to_binary(Data)]
  end.


-ifdef(TEST).

parse_test() ->
  ?assert(parse("") =:= []),
  ?assert(parse("test") =:= [[<<"test">>]]),
  ?assert(parse(lists:duplicate(270, "x")) =:= [[list_to_binary(lists:duplicate(255, "x")), list_to_binary(lists:duplicate(15, "x"))]]).

-endif.
