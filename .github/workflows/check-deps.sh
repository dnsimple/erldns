#!/bin/bash

GITHUB_PR_LABEL="dependencies"

if [ -z "$BRANCH_NAME" ]; then
    echo "Branch name is required"
    exit 1
fi

function check_pr {
    gh pr list --state open --label "$GITHUB_PR_LABEL"
}

# git config user.name "${GITHUB_ACTOR}"
# git config user.email "${GITHUB_ACTOR}@users.noreply.github.com"

_update_output="$(rebar3 update-deps --replace)"

if git diff --exit-code --quiet; then
    echo "No changes to the dependencies"
    exit 0
fi

git checkout -b "$BRANCH_NAME"
git add .
git commit -m "Update dependencies" -m "Updates from \"rebar3 update-deps --replace\":\n\n$_update_output"

git push --set-upstream origin "$BRANCH_NAME"

if [[ $(check_pr) == "" ]]; then
    gh pr create --fill --label "$GITHUB_PR_LABEL"
fi
