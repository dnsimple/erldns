<!--
How to fill out this template:

1. Describe outcomes and intent, not implementation. Reviewers should
   understand WHAT is changing and WHY without reading the diff.
2. Use GitHub keywords to link related issues and PRs:
   https://docs.github.com/en/get-started/writing-on-github/working-with-advanced-formatting/using-keywords-in-issues-and-pull-requests
3. Deployment task and verification lists MUST use GitHub checkboxes
   (`- [ ] ...`), not plain bullets (`- ...`). Plain bullets are not parsed
   as tasks by GitHub or by automation/AI tools.
4. Keep every section. If a section does not apply, write `N/A` as its body.
   Do not delete sections and do not leave placeholder text.
5. Delete every HTML comment (including this one) as you fill in the sections.
   Comments are guidance for the writer and should not remain in the submitted
   PR.
-->

<!--
Describe the intent of the PR. Provide relevant context so a reviewer can
understand how the problem is being solved without reading the diff first.

If the PR performs multiple changes, list them. Use either a bulleted list or
a short narrative paragraph — whichever fits the change best.

Use GitHub keywords to link related issues and PRs, e.g.:

    Fixes #0000
    Belongs to #0000

Delete this comment when you fill in the section.
-->

- Listed change, or use the narrative style


## :clipboard: Deployment Pre/Post tasks

<!--
List any pre-deployment and post-deployment tasks (database migrations,
feature flag flips, manual cache invalidations, secrets rotations, etc.).

REQUIRED FORMAT: each task MUST be a GitHub checkbox so it is tracked as a
task by GitHub, automations, and AI agents:

    - [ ] PRE: Run the migration `add_users_table` on the production database.
    - [ ] POST: Toggle the `new_login_flow` feature flag to ON.

Do NOT use plain bullets (`- ...`) — they will not be picked up as tasks.
Write `N/A` if there are no deployment tasks.

Delete this comment when you fill in the section.
-->

- [ ] 


## :shipit: Deployment Verification

<!--
List the steps you will follow to confirm the successful deployment of the
change.

REQUIRED FORMAT: each verification step MUST be a GitHub checkbox so it is
tracked as a task by GitHub, automations, and AI agents:

    - [ ] `GET /healthz` returns 200.
    - [ ] The new "Sign in with X" button appears on the login page.

Do NOT use plain bullets (`- ...`) — they will not be picked up as tasks.
Write `N/A` if no verification is needed (e.g., docs-only changes).

Delete this comment when you fill in the section.
-->

- [ ] 
