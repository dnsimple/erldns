-module(erldns_pipe_deps).
-moduledoc false.

-export([check/3]).

-doc "Check that the dependencies `Module` declares are in their place in `Pipes`.".
-spec check(module(), erldns_pipeline:deps(), [module() | function()]) -> ok | {error, dynamic()}.
check(Module, Deps, Pipes) ->
    % The module is placed by its first appearance, which "After" always starts with
    {Before, [Module | After]} = lists:splitwith(fun(P) -> P =/= Module end, Pipes),
    IsEarlier = fun(Dep) -> lists:member(Dep, Before) end,
    IsLater = fun(Dep) -> lists:member(Dep, After) andalso not lists:member(Dep, Before) end,
    IsPresent = fun(Dep) -> lists:member(Dep, Pipes) end,
    Prerequisites = maps:get(prerequisites, Deps, []),
    Dependents = maps:get(dependents, Deps, []),
    PreHint = ~"Prerequisite must appear earlier in pipeline",
    DepHint = ~"Dependent must appear later in pipeline",
    maybe
        ok ?= ensure_satisfied(Module, Prerequisites, IsEarlier, IsPresent, PreHint),
        ensure_satisfied(Module, Dependents, IsLater, IsPresent, DepHint)
    end.

-spec ensure_satisfied(Module, Dependencies, IsPlaced, IsPresent, Hint) ->
    ok | {error, dynamic()}
when
    Module :: module(),
    Dependencies :: [erldns_pipeline:dependency()],
    IsPlaced :: fun((module()) -> boolean()),
    IsPresent :: fun((module()) -> boolean()),
    Hint :: binary().
ensure_satisfied(Module, Dependencies, IsPlaced, IsPresent, Hint) ->
    Unsatisfied = [D || D <- Dependencies, not is_satisfied(D, IsPlaced, IsPresent)],
    case Unsatisfied of
        [] ->
            ok;
        [Dependency | _] ->
            Requires = dependency_module(Dependency),
            {error, {unsatisfied_dependency, #{pipe => Module, requires => Requires, hint => Hint}}}
    end.

%% An optional dependency is also satisfied by its absence.
-spec is_satisfied(erldns_pipeline:dependency(), IsPlaced, IsPresent) -> boolean() when
    IsPlaced :: fun((module()) -> boolean()),
    IsPresent :: fun((module()) -> boolean()).
is_satisfied({optional, Dep}, IsPlaced, IsPresent) ->
    IsPlaced(Dep) orelse not IsPresent(Dep);
is_satisfied(Dep, IsPlaced, _) ->
    IsPlaced(Dep).

-spec dependency_module(erldns_pipeline:dependency()) -> module().
dependency_module({optional, Module}) -> Module;
dependency_module(Module) -> Module.
