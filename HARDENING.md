<!-- markdownlint-disable -->

# Hardening Report: docker--cagent-action/v1.5.4

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **docker--cagent-action/v1.5.4** was hardened automatically. 2 finding(s) were identified and resolved across 4 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Rule (a): Direct ${{ }} expression interpolation inside run: shell scripts. In the 'Resolve PR number and comment ID' step, ${{ github.event.pull_request.number }}, ${{ github.event.issue.number }}, and ${{ github.event.comment.id }} are interpolated directly into the shell script body (not via env: block). An attacker who can control PR/issue/comment metadata could inject shell metacharacters. In the 'Evaluate review lock' step, ${{ steps.review-lock.outputs.cache-matched-key }} is interpolated directly into an if-condition in the shell script.

Locations:

- `review-pr/action.yml:95`
- `review-pr/action.yml:98`
- `review-pr/action.yml:110`
- `review-pr/action.yml:160`

### github-env-injection (severity: high)

Multiple run: blocks write values derived from untrusted inputs to $GITHUB_OUTPUT without the required sanitization step (printf '%s' ... | tr -d '\n\r'). (1) 'Resolve PR number and comment ID' step: PR_NUMBER (sourced from ${{ github.event.pull_request.number }} or ${{ github.event.issue.number }}) and COMMENT_ID (sourced from ${{ github.event.comment.id }}) are written directly to $GITHUB_OUTPUT via echo without newline stripping. (2) 'Resolve GitHub token' step: $EXPLICIT_TOKEN (from inputs.github-token, a caller-controlled input) is written to $GITHUB_OUTPUT without sanitization. (3) 'Build review context' step: review_context.md — which contains $EXTRA_PROMPT from inputs.additional-prompt — is written to $GITHUB_OUTPUT via a heredoc with delimiter PROMPT_EOF; if the input contains a line consisting solely of 'PROMPT_EOF', the heredoc terminates early and arbitrary key=value pairs can be injected. (4) 'Collect pending feedback' step: $COMBINED (assembled from downloaded artifact data, which is externally controlled) is written to $GITHUB_OUTPUT via a heredoc with delimiter FEEDBACK_EOF, subject to the same heredoc-injection risk.

Locations:

- `review-pr/action.yml:104`
- `review-pr/action.yml:112`
- `review-pr/action.yml:129`
- `review-pr/action.yml:132`
- `review-pr/action.yml:29039`
- `review-pr/action.yml:24420`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, github-env-injection

**Notes:**

Fixed all script-injection and github-env-injection findings in hardened/action/review-pr/action.yml:

1. **script-injection (lines 95, 98, 110, 160)**: Moved ${{ github.event.pull_request.number }}, ${{ github.event.issue.number }}, ${{ github.event.comment.id }} into the env: block of the 'Resolve PR number and comment ID' step as EVENT_PR_NUMBER, EVENT_ISSUE_NUMBER, EVENT_COMMENT_ID. Moved ${{ steps.review-lock.outputs.cache-matched-key }} into the env: block of the 'Evaluate review lock' step as CACHE_MATCHED_KEY.

2. **github-env-injection (lines 104, 112, 129, 132, ~24420, ~29039)**: Added `printf '%s' "$VAR" | tr -d '\n\r'` sanitization before writing pr-number, comment-id, and token values to $GITHUB_OUTPUT. Replaced fixed heredoc delimiters PROMPT_EOF and FEEDBACK_EOF with randomly generated delimiters using `openssl rand -hex 16` to prevent heredoc injection attacks where attacker-controlled content could contain the delimiter string and inject arbitrary key=value pairs into $GITHUB_OUTPUT.

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed script injection in 5 workflow files by moving all ${{ }} expressions out of run: shell scripts into step env: blocks:

1. self-review-pr-trigger.yml: Moved github.event_name to EVENT_NAME env var.

2. update-docker-agent-version.yml: Moved github.event_name, github.server_url, github.repository, github.run_id to GH_EVENT_NAME, GH_SERVER_URL, GH_REPOSITORY, GH_RUN_ID env vars in the 'Create or update PR' step.

3. release.yml: Moved github.server_url, github.repository, github.run_id to GH_SERVER_URL, GH_REPOSITORY, GH_RUN_ID env vars in the update-self-refs 'Create or update PR' step.

4. test-e2e.yml: Fixed 8 steps across 4 jobs - moved github.event.pull_request.head.repo.full_name, github.event_name, github.repository, steps outputs, github.actor to env vars.

5. test-e2e-reviewer.yml: Fixed 7 steps across 2 jobs - moved github.event.pull_request.head.repo.full_name, github.event_name, github.repository, github.actor, inputs.pr_number, steps outputs to env vars.

### Iteration 3

**Fixes applied:** script-injection, github-env-injection

**Notes:**

Fixed 3 findings across 3 files:
1. test-e2e.yml (script-injection): Quoted all 6 unquoted $TEST_PR_NUMBER expansions in gh api URL paths across test-mention-reply-toplevel and test-mention-reply-inline jobs. Changed `gh api repos/.../issues/$TEST_PR_NUMBER/...` to `gh api "repos/.../issues/$TEST_PR_NUMBER/..."` to prevent shell word-splitting on attacker-controlled input.
2. release.yml (github-env-injection): Replaced fixed 'EOF' heredoc delimiter with a randomized one (`DELIM="NOTES_EOF_$(openssl rand -hex 16)"`) when writing release notes to $GITHUB_OUTPUT in the 'Fetch release notes from GitHub' step of the notify job.
3. update-docker-agent-version.yml (github-env-injection): Added sanitization of VERSION before writing to $GITHUB_OUTPUT: `safe_version=$(printf '%s' "$VERSION" | tr -d '\n\r')` followed by `echo "version=$safe_version" >> "$GITHUB_OUTPUT"`, preventing newline injection from user-controlled workflow_dispatch or repository_dispatch inputs.

### Iteration 4

**Fixes applied:** github-env-injection

**Notes:**

Fixed all three github-env-injection findings:
1. review-pr/action.yml 'Post clean summary' step: Sanitized REPOSITORY via `SAFE_REPOSITORY=$(printf '%s' "$REPOSITORY" | tr -d '\n\r')` before building REVIEW_URL, and sanitized the final URL before writing to $GITHUB_OUTPUT.
2. .github/workflows/review-pr.yml 'Parse comment context' step: Sanitized EVENT_PR_NUMBER and EVENT_PR_HEAD_SHA with `printf '%s' ... | tr -d '\n\r'` before writing pr-number and pr-head-sha to $GITHUB_OUTPUT.
3. .github/workflows/review-pr.yml 'Build thread context' step: Sanitized REPO with `SAFE_REPO=$(printf '%s' "$REPO" | tr -d '\n\r')` at the start of the run block, and replaced all uses of $REPO with $SAFE_REPO throughout the step including the heredoc block written to $GITHUB_OUTPUT.

