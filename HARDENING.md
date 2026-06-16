<!-- markdownlint-disable -->

# Hardening Report: docker--cagent-action/v1.5.5

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `1`

Action **docker--cagent-action/v1.5.5** was hardened automatically. 2 finding(s) were identified and resolved across 3 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Rule (a) violation: Multiple GitHub Actions expressions are directly interpolated inside run: shell commands in review-pr/action.yml.

1. 'Resolve PR number and comment ID' step (line ~98): `PR_NUMBER="${{ github.event.pull_request.number }}"` — the pull request number from the event payload is injected directly into the shell script. An attacker controlling a PR title/branch can craft a PR number field to inject shell metacharacters.

2. Same step (line ~101): `PR_NUMBER="${{ github.event.issue.number }}"` — same issue with the issue number.

3. Same step (line ~113): `COMMENT_ID="${{ github.event.comment.id }}"` — the comment ID from the event payload is injected directly into the shell script.

4. 'Evaluate review lock' step (line ~164): `if [ -n "${{ steps.review-lock.outputs.cache-matched-key }}" ]` — a step output is interpolated directly into the shell condition. Step outputs flow through YAML template substitution before the shell sees them, making this a script-injection risk.

All of these should be moved to env: variables and referenced as $VAR inside the run: block.

Locations:

- `review-pr/action.yml:98`
- `review-pr/action.yml:101`
- `review-pr/action.yml:113`
- `review-pr/action.yml:164`

### github-env-injection (severity: high)

Untrusted input values are written to $GITHUB_OUTPUT without the required sanitization step (printf '%s' ... | tr -d '\n\r').

1. 'Resolve PR number and comment ID' step: $PR_NUMBER (derived from ${{ github.event.pull_request.number }} or ${{ github.event.issue.number }}) is written via `echo "pr-number=$PR_NUMBER" >> $GITHUB_OUTPUT` without sanitization. A newline embedded in the value could inject additional key=value pairs into GITHUB_OUTPUT.

2. Same step: $COMMENT_ID (derived from ${{ github.event.comment.id }}) is written via `echo "comment-id=$COMMENT_ID" >> $GITHUB_OUTPUT` without sanitization.

3. 'Resolve GitHub token' step: $EXPLICIT_TOKEN (from inputs.github-token) and $DEFAULT_TOKEN (from github.token) are written via `echo "token=$EXPLICIT_TOKEN" >> $GITHUB_OUTPUT` and `echo "token=$DEFAULT_TOKEN" >> $GITHUB_OUTPUT` without sanitization. A caller-supplied github-token containing a newline could inject additional outputs.

All writes to $GITHUB_OUTPUT from untrusted sources must be preceded by: `safe=$(printf '%s' "$VAR" | tr -d '\n\r')`

Locations:

- `review-pr/action.yml:107`
- `review-pr/action.yml:115`
- `review-pr/action.yml:133`
- `review-pr/action.yml:136`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, github-env-injection

**Notes:**

Fixed all four script-injection locations and all four github-env-injection locations in review-pr/action.yml:

1. 'Resolve PR number and comment ID' step: Moved github.event.pull_request.number, github.event.issue.number, and github.event.comment.id from inline shell interpolation into the env: block as EVENT_PR_NUMBER, EVENT_ISSUE_NUMBER, EVENT_COMMENT_ID. Added sanitization (printf '%s' | tr -d '\n\r') before writing pr-number and comment-id to $GITHUB_OUTPUT.

2. 'Evaluate review lock' step: Moved steps.review-lock.outputs.cache-matched-key from inline shell interpolation into the env: block as CACHE_MATCHED_KEY, referenced as $CACHE_MATCHED_KEY in the shell condition.

3. 'Resolve GitHub token' step: Added sanitization (printf '%s' | tr -d '\n\r') before writing the token value to $GITHUB_OUTPUT for both the explicit token and default token paths.

### Iteration 2

**Fixes applied:** github-env-injection

**Notes:**

Fixed the github-env-injection vulnerability in review-pr/action.yml's 'Build review context' step (around line 529). Two complementary mitigations were applied: (1) EXTRA_PROMPT is now sanitized with `grep -v '^PROMPT_EOF$'` to strip any line that exactly matches the heredoc delimiter before writing to review_context.md; (2) The heredoc delimiter used when writing to $GITHUB_OUTPUT is now randomized (`PROMPT_EOF_$(openssl rand -hex 8)`) making it practically impossible for an attacker-controlled value to predict and inject the delimiter. Also quoted $GITHUB_OUTPUT properly.

### Iteration 3

**Fixes applied:** github-env-injection

**Notes:**

Fixed heredoc injection vulnerability in the 'Collect pending feedback' step of review-pr/action.yml. Replaced the fixed heredoc delimiter 'FEEDBACK_EOF' with a randomized delimiter 'FEEDBACK_EOF_$(openssl rand -hex 8)' stored in variable FEEDBACK_DELIM. This prevents an attacker from crafting artifact content (FB_PATH, FB_LINE, FB_BODY from downloaded artifacts) that contains a line exactly matching the delimiter, which would terminate the heredoc early and allow injection of arbitrary key=value pairs into $GITHUB_OUTPUT. The fix is consistent with the approach already used in the 'Build review context' step which uses PROMPT_EOF_$(openssl rand -hex 8).

