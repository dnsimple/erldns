%% @author Daniel Luna <daniel@lunas.se>
%% @copyright Various
%% @doc
-module(user_default).
-author('Daniel Luna <daniel@lunas.se>').
-export([help/0]).
-export([p/1, q/0, s/1]).
-export([mm/0, modified_modules/0, lm/0]).
-export([dup/0, xref/0]).
-export([system_started/0, echo_at_node/1]).

help() ->
    shell_default:help(),
    io:format("** user extended commands **~n"),
    io:format("mm()   -- shows a list of modified beam files\n"),
    io:format("lm()   -- loads all modified beam files\n"),
    io:format("p(X)   -- prints X to terminal using ~~p\n"),
    io:format("s(X)   -- prints X to terminal using ~~s\n"),
    io:format("dup()  -- compiles and loads new code on a full release\n"),
    true.

p(X) ->
    io:format("~p~n", [X]).

q() ->
    io:format("If you actually want to bring down the system, "
              "use erlang:halt().~nIf you want to quit your shell, "
              "use C-d.~n").

s(X) ->
    io:format("~s~n", [X]).

lm() ->
    [c:l(M) || M <- mm()].

%% mm/0 et al by Vladimir Sekissov, with additions by Daniel Luna
%% http://erlang.org/pipermail/erlang-questions/2004-November/013577.html
mm() ->
    modified_modules().

modified_modules() ->
    %% Indirection to trick xref.  code:get_mode() was added in R16.
    try call(code, get_mode, []) of
        embedded ->
            modified_modules_embedded();
        interactive ->
            [M || {M, _} <- code:all_loaded(), module_modified(M) == true]
    catch
        error:undef ->
            modified_modules_embedded()
    end.

call(M, F, A) ->
    apply(M, F, A).

modified_modules_embedded() ->
    Files =
        lists:flatmap(fun(Dir) -> filelib:wildcard([Dir, "/*.beam"]) end,
                      code:get_path()),
    Loaded = code:all_loaded(),
    element(
      1,
      lists:foldl(
        fun(File, {Modified, RemainingLoaded}) ->
                M = list_to_atom(filename:basename(filename:rootname(File))),
                case lists:keytake(M, 1, RemainingLoaded) of
                    {value, {M, _}, NewRemainingLoaded} ->
                        case module_modified(M) of
                            true ->
                                {[M | Modified], NewRemainingLoaded};
                            false ->
                                {Modified, NewRemainingLoaded}
                        end;
                    false ->
                        {[M | Modified], RemainingLoaded}
                end
        end,
        {[], Loaded},
        Files)).

module_modified(Module) ->
    case code:is_loaded(Module) of
        {file, preloaded} ->
            false;
        {file, Path} ->
            CompileOpts = proplists:get_value(compile, Module:module_info()),
            CompileTime = proplists:get_value(time, CompileOpts),
            Src = proplists:get_value(source, CompileOpts),
            module_modified(Path, CompileTime, Src);
        _ ->
            false
    end.

module_modified(Path, PrevCompileTime, PrevSrc) ->
    case find_module_file(Path) of
        false ->
            false;
        ModPath ->
            {ok, {_, [{_, CB}]}} = beam_lib:chunks(ModPath, ["CInf"]),
            CompileOpts =  binary_to_term(CB),
            CompileTime = proplists:get_value(time, CompileOpts),
            Src = proplists:get_value(source, CompileOpts),
            not (CompileTime == PrevCompileTime) and (Src == PrevSrc)
    end.

find_module_file(Path) ->
    case file:read_file_info(Path) of
        {ok, _} ->
            Path;
        _ ->
            %% may be the path was changed?
            case code:where_is_file(filename:basename(Path)) of
                non_existing ->
                    false;
                NewPath ->
                    NewPath
            end
    end.

%% dirty upgrade
dup() ->
    Res = os:cmd("cd ../../ && "
                 "PATH=$(echo $PATH | sed 'sx.*/rel/full/[^:]*:xx') "
                 "make apps xref refresh_full; "
                 "echo \" $?\""),
    case lists:reverse(Res) of
        "\n0 " ++ _ -> {ok, lm()};
        _ -> s(Res), {error, upgrade_failed}
    end.

xref() ->
    Res = os:cmd("cd ../../ && "
                 "PATH=$(echo $PATH | sed 'sx.*/rel/full/[^:]*:xx') "
                 "make xref; "
                 "echo \" $?\""),
    case lists:reverse(Res) of
        "\n0 " ++ _ -> ok;
        _ -> s(Res), error
    end.

system_started() ->
    Info = application_controller:info(),
    case lists:keyfind(loading, 1, Info) of
        {loading, []} ->
            case lists:keyfind(starting, 1, Info) of
                {starting, []} ->
                    true;
                {starting, _} ->
                    false
            end;
        {loading, _} ->
            false
    end.

echo_at_node(Data) ->
    erlang:group_leader(whereis(user), self()),
    io:format("~s~n", [Data]).
