<!-- markdownlint-disable -->

# Hardening Report: docker--cagent-action/v1.5.5

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **docker--cagent-action/v1.5.5** was hardened automatically. 2 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Rule (a): Direct `${{ }}` expression interpolation inside `run:` shell scripts in review-pr/action.yml. In the 'Resolve PR number and comment ID' step, the run block directly assigns `PR_NUMBER="${{ github.event.pull_request.number }}"`, `PR_NUMBER="${{ github.event.issue.number }}"`, and `COMMENT_ID="${{ github.event.comment.id }}"` — all attacker-controllable github context values substituted directly into shell code before the shell ever sees them. In the 'Evaluate review lock' step, `if [ -n "${{ steps.review-lock.outputs.cache-matched-key }}" ]; then` interpolates a step output directly into the shell command string.

Locations:

- `review-pr/action.yml:98`
- `review-pr/action.yml:101`
- `review-pr/action.yml:113`
- `review-pr/action.yml:170`

### github-env-injection (severity: high)

Multiple steps in review-pr/action.yml write untrusted values to $GITHUB_OUTPUT without the required sanitization step (`printf '%s' ... | tr -d '\n\r'`). (1) 'Resolve PR number and comment ID' step: writes `pr-number=$PR_NUMBER` and `comment-id=$COMMENT_ID` to $GITHUB_OUTPUT, where $PR_NUMBER is set directly from `${{ github.event.pull_request.number }}`/`${{ github.event.issue.number }}` and $COMMENT_ID from `${{ github.event.comment.id }}` inside the run block — no newline stripping applied. (2) 'Resolve GitHub token' step: writes `token=$EXPLICIT_TOKEN` and `token=$DEFAULT_TOKEN` to $GITHUB_OUTPUT, where EXPLICIT_TOKEN holds `${{ inputs.github-token }}` (caller-controlled) and DEFAULT_TOKEN holds `${{ github.token }}` — neither is sanitized before the write. (3) 'Build review context' step: writes `review_prompt<<PROMPT_EOF ... PROMPT_EOF` to $GITHUB_OUTPUT using `cat review_context.md`, which contains the unsanitized `$EXTRA_PROMPT` value (from `inputs.additional-prompt`); a newline followed by `PROMPT_EOF` in the input would break the heredoc delimiter and allow injection of arbitrary key=value pairs into $GITHUB_OUTPUT.

Locations:

- `review-pr/action.yml:107`
- `review-pr/action.yml:115`
- `review-pr/action.yml:133`
- `review-pr/action.yml:136`
- `review-pr/action.yml:490`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, github-env-injection

**Notes:**

Fixed all findings in hardened/action/review-pr/action.yml:

1. script-injection (lines 98, 101, 113, 170):
   - 'Resolve PR number and comment ID' step: Moved github.event.pull_request.number, github.event.issue.number, and github.event.comment.id from inline ${{ }} expressions in the run block to the step's env: block as EVENT_PR_NUMBER, EVENT_ISSUE_NUMBER, and EVENT_COMMENT_ID.
   - 'Evaluate review lock' step: Moved steps.review-lock.outputs.cache-matched-key from inline ${{ }} in the run block to the step's env: block as CACHE_MATCHED_KEY.

2. github-env-injection (lines 107, 115, 133, 136, 490):
   - 'Resolve PR number and comment ID' step: Added printf '%s' ... | tr -d '\n\r' sanitization before writing pr-number and comment-id to $GITHUB_OUTPUT.
   - 'Resolve GitHub token' step: Added printf '%s' ... | tr -d '\n\r' sanitization before writing token to $GITHUB_OUTPUT.
   - 'Build review context' step: Replaced the static PROMPT_EOF heredoc delimiter with a randomly generated delimiter (PROMPT_EOF_$(openssl rand -hex 16)) to prevent heredoc injection via user-controlled content in inputs.additional-prompt.

