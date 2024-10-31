#!/bin/bash -e

GITHUB_PR_LABEL="dependencies"
COMMIT_TITLE="Update dependencies"

if [ -z "$BRANCH_NAME" ]; then
    echo "Branch name is required"
    exit 1
fi

function check_pr {
    gh pr list --state open --label "$GITHUB_PR_LABEL"
}

git config user.name "${GITHUB_ACTOR}"
git config user.email "${GITHUB_ACTOR}@users.noreply.github.com"

_update_output="$(TERM=dumb rebar3 update-deps --replace)"

if git diff --exit-code --quiet; then
    echo "No changes to the dependencies"
    exit 0
else
    echo "Detected changes to dependencies"
fi

git checkout -b "$BRANCH_NAME"
git add .

git commit -F- <<EOF
$COMMIT_TITLE

Updates from "rebar3 update-deps --replace":

$_update_output
EOF

git push --set-upstream origin "$BRANCH_NAME"

if [[ $(check_pr) == "" ]]; then
    gh pr create \
        --label "$GITHUB_PR_LABEL" \
        --title "$COMMIT_TITLE" \
        --body-file - <<EOF
This PR updates the dependencies to their latest versions.

The following changes were made from \`rebar3 update-deps --replace\`:

\`\`\`
$_update_output
\`\`\`
EOF
fi
