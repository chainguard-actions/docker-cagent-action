<!-- markdownlint-disable -->

# Hardening Report: docker--cagent-action--review-pr/v1.5.5

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **docker--cagent-action--review-pr/v1.5.5** was hardened automatically. 2 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): Multiple `${{ ... }}` expressions are interpolated directly inside `run:` shell blocks in action.yml, bypassing shell quoting and enabling script injection.

1. Line 98: `PR_NUMBER="${{ github.event.pull_request.number }}"` — attacker-controlled PR title/event data injected into shell.
2. Line 101: `PR_NUMBER="${{ github.event.issue.number }}"` — same step, issue number interpolated directly.
3. Line 113: `COMMENT_ID="${{ github.event.comment.id }}"` — comment ID from event interpolated directly.
4. Line 166: `if [ -n "${{ steps.review-lock.outputs.cache-matched-key }}" ]` — step output interpolated directly into shell condition.

All four should be moved to `env:` variables and referenced as `"$VAR"` in the shell script.

Locations:

- `action.yml:98`
- `action.yml:101`
- `action.yml:113`
- `action.yml:166`

### github-env-injection (severity: high)

Multiple untrusted values are written to `$GITHUB_OUTPUT` without the required `printf '%s' ... | tr -d '\n\r'` sanitization step:

1. Lines 98+107: `${{ github.event.pull_request.number }}` is assigned to `PR_NUMBER` and written to `$GITHUB_OUTPUT` via `echo "pr-number=$PR_NUMBER" >> $GITHUB_OUTPUT` with no newline sanitization.
2. Lines 101+107: `${{ github.event.issue.number }}` is similarly assigned to `PR_NUMBER` and written to `$GITHUB_OUTPUT`.
3. Lines 113+115: `${{ github.event.comment.id }}` is assigned to `COMMENT_ID` and written to `$GITHUB_OUTPUT` via `echo "comment-id=$COMMENT_ID" >> $GITHUB_OUTPUT` with no sanitization.
4. Lines 133/136: `inputs.github-token` (via `EXPLICIT_TOKEN` env var) is written to `$GITHUB_OUTPUT` via `echo "token=$EXPLICIT_TOKEN" >> $GITHUB_OUTPUT` without sanitization.
5. Build review context step (~line 700+): `inputs.additional-prompt` (via `EXTRA_PROMPT` env var) is appended to `review_context.md` and then the entire file is written to `$GITHUB_OUTPUT` via `cat review_context.md >> $GITHUB_OUTPUT` without sanitization — a newline in the input could inject arbitrary key=value pairs into GITHUB_OUTPUT.

Locations:

- `action.yml:107`
- `action.yml:115`
- `action.yml:133`
- `action.yml:136`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, github-env-injection

**Notes:**

Fixed all script-injection and github-env-injection findings in hardened/action/action.yml:

1. **script-injection (lines 98, 101, 113)**: Moved `${{ github.event.pull_request.number }}`, `${{ github.event.issue.number }}`, and `${{ github.event.comment.id }}` from inline shell interpolation to `env:` block variables (`EVENT_PR_NUMBER`, `EVENT_ISSUE_NUMBER`, `EVENT_COMMENT_ID`).

2. **script-injection (line 166)**: Moved `${{ steps.review-lock.outputs.cache-matched-key }}` to an `env:` block variable (`CACHE_MATCHED_KEY`) in the 'Evaluate review lock' step.

3. **github-env-injection (lines 107, 115)**: Added `printf '%s' ... | tr -d '\n\r'` sanitization before writing `pr-number` and `comment-id` to `$GITHUB_OUTPUT`.

4. **github-env-injection (lines 133, 136)**: Added `printf '%s' ... | tr -d '\n\r'` sanitization before writing `token` to `$GITHUB_OUTPUT` in the 'Resolve GitHub token' step.

5. **github-env-injection (Build review context step)**: Changed the fixed `PROMPT_EOF` heredoc delimiter to a random one (`PROMPT_EOF_$(openssl rand -hex 16)`) to prevent injection via user-controlled `inputs.additional-prompt` content that could contain the delimiter string on its own line.

### Iteration 2

**Fixes applied:** github-env-injection

**Notes:**

Fixed two github-env-injection vulnerabilities in hardened/action/action.yml:
1. 'Collect pending feedback' step (line ~558): Replaced fixed heredoc delimiter 'FEEDBACK_EOF' with a randomly generated delimiter using `openssl rand -hex 16`, stored in FEEDBACK_DELIM. This prevents an attacker from crafting artifact content containing 'FEEDBACK_EOF' on its own line to prematurely terminate the heredoc and inject arbitrary key=value pairs into $GITHUB_OUTPUT.
2. 'Post clean summary' step (line ~762): Added sanitization of REVIEW_URL (which contains $REPOSITORY from github.repository context) using `printf '%s' "$REVIEW_URL" | tr -d '\n\r'` before writing to $GITHUB_OUTPUT, preventing newline injection attacks.

