-module(txt_test).

-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").

-define(MAX_TXT_SIZE, 255).

%% Known failure cases:
%% \
%% "
%% "\"
parse_test() ->
    ?assertEqual([], erldns_txt:parse("")),
    ?assertEqual([[<<"test">>]], erldns_txt:parse("test")),
    ?assertEqual([[list_to_binary(lists:duplicate(255, "x")), list_to_binary(lists:duplicate(15, "x"))]], erldns_txt:parse(lists:duplicate(270, "x"))),
    ?assertEqual([[<<"test">>]], erldns_txt:parse(<<"test">>)),
    ?assertEqual([[<<"test">>], [<<"test">>]], erldns_txt:parse("\"test\" \"test\"")),
    ?assertEqual([[<<"\\">>]], erldns_txt:parse("\\")),
    ?assertEqual([[<<"test\\;">>]], erldns_txt:parse("test\\;")),
    ?assertEqual([[<<"test\\">>]], erldns_txt:parse("test\\")).

proper_test_() ->
    [] = proper:module(?MODULE, [{to_file, user}, {numtests, 1000}]).

check_bblist([]) ->
    true;
check_bblist([[Binary] | Rest]) when is_binary(Binary) andalso size(Binary) =< ?MAX_TXT_SIZE ->
    check_bblist(Rest);
check_bblist(_) ->
    false.

%% ASCII Strings without " nor end in \
quoteless_ascii_string1() ->
    list(oneof([integer(0, 33), integer(35, 255)])).

quoteless_ascii_string() ->
    ?SUCHTHAT(
        String,
        quoteless_ascii_string1(),
        begin
            case lists:reverse(String) of
                [92 | _] ->
                    false;
                _ ->
                    true
            end
        end
    ).

quoted_ascii_string1() ->
    %% " has character code 34.
    ?LET(String, quoteless_ascii_string(), [34] ++ String ++ [34]).

quoted_ascii_string() ->
    ?SUCHTHAT(
        String,
        quoted_ascii_string1(),
        begin
            case lists:reverse(String) of
                % "\
                [34, 92 | _] ->
                    false;
                _ ->
                    true
            end
        end
    ).

quoted_and_unquoted_ascii_string_unflattened() ->
    list(oneof([quoted_ascii_string(), quoteless_ascii_string()])).

quoted_and_unquoted_ascii_string() ->
    ?LET(StringList, quoted_and_unquoted_ascii_string_unflattened(), lists:flatten(StringList)).

prop_parse_holds_type() ->
    ?FORALL(
        ASCIIString,
        quoted_and_unquoted_ascii_string(),
        begin
            BinaryOfBinaryList = erldns_txt:parse(ASCIIString),
            check_bblist(BinaryOfBinaryList)
        end
    ).
