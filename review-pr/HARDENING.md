<!-- markdownlint-disable -->

# Hardening Report: docker--cagent-action--review-pr/v1.5.4

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **docker--cagent-action--review-pr/v1.5.4** was hardened automatically. 5 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Rule (a): Direct ${{ }} expression interpolation inside run: shell blocks in the 'Resolve PR number and comment ID' step. Three github context values are interpolated directly into shell commands: `PR_NUMBER="${{ github.event.pull_request.number }}"`, `PR_NUMBER="${{ github.event.issue.number }}"`, and `COMMENT_ID="${{ github.event.comment.id }}"`. These values are attacker-controllable (e.g. via crafted PR/issue/comment events) and are substituted into the shell script before the shell parses it, enabling command injection.

Locations:

- `action.yml:95`
- `action.yml:98`
- `action.yml:104`

### script-injection (severity: high)

Rule (a): Direct ${{ }} expression interpolation inside a run: shell block in the 'Evaluate review lock' step. The expression `${{ steps.review-lock.outputs.cache-matched-key }}` is interpolated directly into the shell condition: `if [ -n "${{ steps.review-lock.outputs.cache-matched-key }}" ]`. Step outputs are workflow-controllable and must not be interpolated directly into run: blocks.

Locations:

- `action.yml:131`

### github-env-injection (severity: high)

The 'Resolve PR number and comment ID' step assigns github context values directly inside the run: block (`PR_NUMBER="${{ github.event.pull_request.number }}"`, `PR_NUMBER="${{ github.event.issue.number }}"`, `COMMENT_ID="${{ github.event.comment.id }}"`), then writes them to $GITHUB_OUTPUT via `echo "pr-number=$PR_NUMBER" >> $GITHUB_OUTPUT` and `echo "comment-id=$COMMENT_ID" >> $GITHUB_OUTPUT` without the required sanitization step (`printf '%s' ... | tr -d '\n\r'`). An attacker can inject newlines into these values to poison subsequent GITHUB_OUTPUT entries.

Locations:

- `action.yml:100`
- `action.yml:106`

### github-env-injection (severity: high)

The 'Resolve GitHub token' step writes `$EXPLICIT_TOKEN` (sourced from `inputs.github-token` via env:) and `$DEFAULT_TOKEN` (sourced from `github.token` via env:) to $GITHUB_OUTPUT without sanitization: `echo "token=$EXPLICIT_TOKEN" >> $GITHUB_OUTPUT` and `echo "token=$DEFAULT_TOKEN" >> $GITHUB_OUTPUT`. Although tokens are not typically attacker-controlled, they are inputs.*  and github.* values written to the special environment file without the required `tr -d '\n\r'` sanitization.

Locations:

- `action.yml:115`
- `action.yml:117`

### github-env-injection (severity: high)

The 'Post clean summary' step writes `$REVIEW_URL` (derived from `$REPOSITORY` from `github.repository` and `$PR_NUMBER` from `steps.resolve-context.outputs.pr-number`, both workflow-controlled) to $GITHUB_OUTPUT via `echo "review-url=$REVIEW_URL" >> $GITHUB_OUTPUT` without sanitization. A newline in either source value could poison subsequent GITHUB_OUTPUT entries.

Locations:

- `action.yml:484`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, github-env-injection

**Notes:**

Fixed all 5 findings in hardened/action/action.yml:

1. **script-injection (lines 95, 98, 104)** — 'Resolve PR number and comment ID' step: Moved `${{ github.event.pull_request.number }}`, `${{ github.event.issue.number }}`, and `${{ github.event.comment.id }}` out of the shell script body and into the step's `env:` block as `EVENT_PR_NUMBER`, `EVENT_ISSUE_NUMBER`, and `EVENT_COMMENT_ID`. These are now referenced as plain shell variables.

2. **script-injection (line 131)** — 'Evaluate review lock' step: Moved `${{ steps.review-lock.outputs.cache-matched-key }}` out of the shell `if` condition and into the step's `env:` block as `CACHE_MATCHED_KEY`. The condition now uses `$CACHE_MATCHED_KEY`.

3. **github-env-injection (lines 100, 106)** — 'Resolve PR number and comment ID' step: Added `printf '%s' "$VAR" | tr -d '\n\r'` sanitization before writing `pr-number` and `comment-id` to `$GITHUB_OUTPUT`.

4. **github-env-injection (lines 115, 117)** — 'Resolve GitHub token' step: Added `printf '%s' "$VAR" | tr -d '\n\r'` sanitization before writing `token` to `$GITHUB_OUTPUT` in both branches.

5. **github-env-injection (line 484)** — 'Post clean summary' step: Added `printf '%s' "$REVIEW_URL" | tr -d '\n\r'` sanitization before writing `review-url` to `$GITHUB_OUTPUT`.

### Iteration 2

**Fixes applied:** github-env-injection

**Notes:**

Fixed the heredoc injection vulnerability in the 'Build review context' step of action.yml. Replaced the fixed heredoc delimiter 'PROMPT_EOF' with a randomly-generated delimiter 'PROMPT_EOF_$(openssl rand -hex 16)'. This prevents an attacker from injecting arbitrary key=value pairs into $GITHUB_OUTPUT by supplying an additional-prompt input containing the literal string 'PROMPT_EOF' on its own line, since the random delimiter cannot be predicted by the caller.

