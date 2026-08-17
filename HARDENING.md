<!-- markdownlint-disable -->

# Hardening Report: docker--cagent-action/v1.5.5

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **docker--cagent-action/v1.5.5** was hardened automatically. 2 finding(s) were identified and resolved across 4 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Rule (a): Direct ${{ }} expression interpolation inside run: blocks. In the 'Resolve PR number and comment ID' step, three github context values are interpolated directly into shell code: `PR_NUMBER="${{ github.event.pull_request.number }}"`, `PR_NUMBER="${{ github.event.issue.number }}"`, and `COMMENT_ID="${{ github.event.comment.id }}"`. An attacker who can control these event fields (e.g., via a crafted PR title or comment) could inject shell metacharacters. These values should be passed via env: variables instead. Additionally, in the 'Evaluate review lock' step, `${{ steps.review-lock.outputs.cache-matched-key }}` is interpolated directly into the run: block shell condition: `if [ -n "${{ steps.review-lock.outputs.cache-matched-key }}" ]`.

Locations:

- `review-pr/action.yml:94`
- `review-pr/action.yml:97`
- `review-pr/action.yml:104`
- `review-pr/action.yml:150`

### github-env-injection (severity: high)

Untrusted values are written to $GITHUB_OUTPUT without the required sanitization step (`printf '%s' ... | tr -d '\n\r'`). (1) In the 'Resolve PR number and comment ID' step, PR_NUMBER is derived from ${{ github.event.pull_request.number }} and ${{ github.event.issue.number }} (attacker-controlled via PR/issue events) and written directly: `echo "pr-number=$PR_NUMBER" >> $GITHUB_OUTPUT`. Similarly, COMMENT_ID is derived from ${{ github.event.comment.id }} and written: `echo "comment-id=$COMMENT_ID" >> $GITHUB_OUTPUT`. (2) In the 'Resolve GitHub token' step, $EXPLICIT_TOKEN (sourced from inputs.github-token, a caller-controlled input) is written unsanitized: `echo "token=$EXPLICIT_TOKEN" >> $GITHUB_OUTPUT`. A newline embedded in any of these values could inject arbitrary key=value pairs into GITHUB_OUTPUT.

Locations:

- `review-pr/action.yml:101`
- `review-pr/action.yml:105`
- `review-pr/action.yml:120`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, github-env-injection

**Notes:**

Fixed all four script-injection locations and three github-env-injection locations in hardened/action/review-pr/action.yml:

1. 'Resolve PR number and comment ID' step: Moved github.event.pull_request.number, github.event.issue.number, and github.event.comment.id expressions from direct shell interpolation into the env: block (as EVENT_PR_NUMBER, EVENT_ISSUE_NUMBER, EVENT_COMMENT_ID). Added printf '%s' ... | tr -d '\n\r' sanitization before writing pr-number and comment-id to $GITHUB_OUTPUT.

2. 'Resolve GitHub token' step: Added printf '%s' ... | tr -d '\n\r' sanitization for both EXPLICIT_TOKEN and DEFAULT_TOKEN before writing the token value to $GITHUB_OUTPUT.

3. 'Evaluate review lock' step: Moved steps.review-lock.outputs.cache-matched-key from direct shell interpolation in the if condition into the env: block as CACHE_MATCHED_KEY, and updated the shell condition to use $CACHE_MATCHED_KEY.

### Iteration 2

**Fixes applied:** script-injection, github-env-injection

**Notes:**

Fixed all 7 findings across 6 files:

1. self-review-pr-trigger.yml: Moved ${{ github.event_name }} to env block as EVENT_NAME, replaced in printf and if-condition.

2. test-e2e.yml (6 locations): Fixed Check if fork PR steps in test-pirate-agent, test-mention-reply-toplevel, and test-mention-reply-inline by moving HEAD_REPO/EVENT_NAME/REPOSITORY to env blocks. Fixed Validate output and exit code and Verify invalid agent failed by moving OUTPUT_FILE/EXIT_CODE to env. Fixed Assert should-reply output steps by moving all step outputs and github.actor to env blocks. Fixed Assert inline outputs by moving IS_INLINE/IN_REPLY_TO_ID/EXPECTED_ID to env.

3. test-e2e-reviewer.yml (3 locations): Fixed Check if fork PR steps in both top-level-mention and inline-mention jobs. Fixed both Report outcome steps by moving all step outputs to env blocks.

4. release.yml (line 380): Moved ${{ github.server_url }}, ${{ github.repository }}, ${{ github.run_id }} to env block as SERVER_URL, REPOSITORY, RUN_ID and replaced in heredoc.

5. update-docker-agent-version.yml (line 130): Moved ${{ github.event_name }}, ${{ github.server_url }}, ${{ github.repository }}, ${{ github.run_id }} to env block and replaced in both heredoc instances.

6. review-pr/action.yml (line 570): Replaced fixed PROMPT_EOF delimiter with a random one using openssl rand -hex 16 to prevent heredoc injection from user-controlled inputs.additional-prompt.

7. review-pr/action.yml (line 655): Added sanitization with printf '%s' "$REVIEW_URL" | tr -d '\n\r' before writing review-url to $GITHUB_OUTPUT.

### Iteration 3

**Fixes applied:** script-injection, github-env-injection

**Notes:**

Fixed all 4 findings across 4 workflow files:

1. test-e2e-reviewer.yml (script-injection): Moved ${{ github.actor }}, ${{ inputs.pr_number }}, and ${{ steps.create-anchor.outputs.test_comment_id }} out of run: shell strings into env: blocks for the 'Write synthetic issue_comment event' step (top-level-mention job), 'Write synthetic pull_request_review_comment event' step (inline-mention job), and 'Cleanup anchor and replies' step (inline-mention job).

2. test-e2e.yml (script-injection): Moved ${{ github.actor }} and ${{ steps.create-anchor.outputs.test_comment_id }} out of run: shell strings into env: blocks for the 'Write synthetic issue_comment event' step (test-mention-reply-toplevel job) and 'Write synthetic pull_request_review_comment event' step (test-mention-reply-inline job).

3. update-docker-agent-version.yml (github-env-injection): Added `safe_version=$(printf '%s' "$VERSION" | tr -d '\n\r')` before writing version to $GITHUB_OUTPUT to prevent newline injection from user-controlled inputs.

4. review-pr.yml (github-env-injection): Added `tr -d '\n\r'` sanitization for comment-author and comment-in-reply-to-id in the 'Read context' step (resolve-context job), and for comment-author and parent-id in the 'Parse comment context' step (reply-to-feedback job).

### Iteration 1

**Fixes applied:** github-env-injection

**Notes:**

Fixed the github-env-injection finding in hardened/action/review-pr/action.yml. In the 'Build review context' step, the untrusted EXTRA_PROMPT value (from inputs.additional-prompt) was written to review_context.md without sanitization before being piped to $GITHUB_OUTPUT. Added sanitization: `SAFE_EXTRA_PROMPT=$(printf '%s' "$EXTRA_PROMPT" | tr -d '\n\r')` and replaced the `echo "$EXTRA_PROMPT"` with `echo "$SAFE_EXTRA_PROMPT"`. This strips newlines and carriage returns from the caller-controlled input, preventing injection of arbitrary key=value pairs or heredoc terminators into $GITHUB_OUTPUT.

