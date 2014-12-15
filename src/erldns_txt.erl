%% Copyright (c) 2012-2014, Aetrion LLC
%%
%% Permission to use, copy, modify, and/or distribute this software for any
%% purpose with or without fee is hereby granted, provided that the above
%% copyright notice and this permission notice appear in all copies.
%%
%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
%% WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
%% MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
%% ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
%% WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
%% ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
%% OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

%% @doc Functions related to TXT record parsing.
-module(erldns_txt).

-include("erldns.hrl").

-export([parse/1]).

-define(MAX_TXT_SIZE, 255).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

%% Public API

%% @doc Parse a string into a collection of bit strings, each no longer than
%% 255 characters.
-spec parse(binary() | string()) -> [] | [[binary()]].
parse(Binary) when is_binary(Binary) -> parse(binary_to_list(Binary));
parse([]) -> [];
parse([C|Rest]) -> parse_char([C|Rest], C, Rest, [], false).

-spec parse(string(), string(), [string()], boolean()) -> [binary()].
parse(String, [], [], _) -> [split(String)];
parse(_, [], Tokens, _) -> Tokens;
parse(String, [C|Rest], Tokens, Escaped) -> parse_char(String, C, Rest, Tokens, Escaped).
parse(_, [], Tokens, CurrentToken, true) -> Tokens ++ [CurrentToken]; % Last character is escaped
parse(String, [C|Rest], Tokens, CurrentToken, Escaped) -> parse_char(String, C, Rest, Tokens, CurrentToken, Escaped).

%% @doc Do something with the given character. The rules are as follows:
%% * A quote starts/ends a token.
%% * Any other character is considered part of the current token.
-spec parse_char(string(), char(), string(), [string()], boolean()) -> any().
parse_char(String, $", Rest, Tokens, _) -> parse(String, Rest, Tokens, [], false);
parse_char(String, _, Rest, Tokens, _) -> parse(String, Rest, Tokens, false).

parse_char(String, $", Rest, Tokens, CurrentToken, false) ->
    parse(String, Rest, Tokens ++ [split(CurrentToken)], false);
parse_char(String, $", Rest, Tokens, CurrentToken, true) ->
    parse(String, Rest, Tokens, CurrentToken ++ [$"], false);
parse_char(String, $\\, Rest, Tokens, CurrentToken, false) ->
    parse(String, Rest, Tokens, CurrentToken, true);
parse_char(String, $\\, Rest, Tokens, CurrentToken, true) ->
    parse(String, Rest, Tokens, CurrentToken ++ [$\\], false);
parse_char(String, C, Rest, Tokens, CurrentToken, _) ->
    parse(String, Rest, Tokens, CurrentToken ++ [C], false).

%% @doc Split the given string into a list of bit strings, with each element
%% limited to 255 characters or less.
-spec split(string()) -> [binary()].
split(Data) -> split(Data, []).

%% Internal recursive split function.
-spec split(string(), [binary()]) -> [binary()].
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
    ?assertEqual(parse(""), []),
    ?assertEqual(parse("test"), [[<<"test">>]]),
    ?assertEqual(parse(lists:duplicate(270, "x")), [[list_to_binary(lists:duplicate(255, "x")),
                                                     list_to_binary(lists:duplicate(15, "x"))]]),
    ?assertEqual(parse(<<"test">>), [[<<"test">>]]),
    ?assertEqual(parse("\"test\" \"test\""), [[<<"test">>], [<<"test">>]]),
    ?assertEqual(parse("\\"), [[<<"\\">>]]),
    ?assertEqual(parse("test\\;"), [[<<"test\\;">>]]),
    ?assertEqual(parse("test\\"), [[<<"test\\">>]]).
%%     ?assertEqual(parse("\"test\"\""), [[<<"test\"">>]]).

-endif.
