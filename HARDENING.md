<!-- markdownlint-disable -->

# Hardening Report: docker--cagent-action/v1.5.4

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `1`

Action **docker--cagent-action/v1.5.4** was hardened automatically. 5 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Rule (a): The 'Resolve PR number and comment ID' step in review-pr/action.yml directly interpolates GitHub Actions expressions inside the run: shell script without routing through env: variables first. The expressions `${{ github.event.pull_request.number }}`, `${{ github.event.issue.number }}`, and `${{ github.event.comment.id }}` are substituted directly into the shell command string before the shell parses it, allowing an attacker to inject arbitrary shell commands via a crafted event payload (e.g., a PR title or comment containing shell metacharacters).

Offending lines:
  PR_NUMBER="${{ github.event.pull_request.number }}"
  PR_NUMBER="${{ github.event.issue.number }}"
  COMMENT_ID="${{ github.event.comment.id }}"

Locations:

- `review-pr/action.yml:95`
- `review-pr/action.yml:98`
- `review-pr/action.yml:110`

### script-injection (severity: high)

Rule (a): The 'Evaluate review lock' step in review-pr/action.yml directly interpolates `${{ steps.review-lock.outputs.cache-matched-key }}` inside the run: shell script. This expression is substituted into the shell command string before the shell parses it. A cache key value containing shell metacharacters could alter the script's control flow.

Offending line:
  if [ -n "${{ steps.review-lock.outputs.cache-matched-key }}" ]; then

Locations:

- `review-pr/action.yml:162`

### github-env-injection (severity: high)

The 'Resolve PR number and comment ID' step writes $PR_NUMBER and $COMMENT_ID to $GITHUB_OUTPUT without sanitization. $PR_NUMBER is sourced from the inputs.pr-number input (via env var $PR_NUMBER_INPUT) or directly from ${{ github.event.pull_request.number }} / ${{ github.event.issue.number }} interpolated in the run block. $COMMENT_ID is sourced from inputs.comment-id or ${{ github.event.comment.id }}. Neither value is passed through `printf '%s' ... | tr -d '\n\r'` before being written to $GITHUB_OUTPUT, allowing newline injection that could set arbitrary output variables.

Locations:

- `review-pr/action.yml:104`
- `review-pr/action.yml:112`

### github-env-injection (severity: high)

The 'Resolve GitHub token' step writes $EXPLICIT_TOKEN (sourced from inputs.github-token via env var) and $DEFAULT_TOKEN (sourced from github.token via env var) to $GITHUB_OUTPUT without sanitization. Neither value is passed through `printf '%s' ... | tr -d '\n\r'` before the write. A token value containing a newline character could inject additional key=value pairs into $GITHUB_OUTPUT, potentially overwriting other outputs.

Offending lines:
  echo "token=$EXPLICIT_TOKEN" >> $GITHUB_OUTPUT
  echo "token=$DEFAULT_TOKEN" >> $GITHUB_OUTPUT

Locations:

- `review-pr/action.yml:131`
- `review-pr/action.yml:134`

### github-env-injection (severity: high)

The 'Build review context' step writes the contents of review_context.md to $GITHUB_OUTPUT using a heredoc. The file includes $EXTRA_PROMPT (sourced from inputs.additional-prompt via env var), which is caller-controlled. If the prompt contains the heredoc delimiter string 'PROMPT_EOF' on its own line, it would prematurely terminate the heredoc and allow injection of arbitrary content into $GITHUB_OUTPUT. No sanitization is applied before the write.

Offending block:
  { echo "review_prompt<<PROMPT_EOF"; cat review_context.md; echo "PROMPT_EOF"; } >> $GITHUB_OUTPUT

Locations:

- `review-pr/action.yml:285`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, github-env-injection

**Notes:**

Fixed all 5 findings in review-pr/action.yml:

1. **script-injection (Resolve PR number and comment ID, lines 95/98/110)**: Moved `${{ github.event.pull_request.number }}`, `${{ github.event.issue.number }}`, and `${{ github.event.comment.id }}` out of the run: shell script into the step's env: block as EVENT_PR_NUMBER, EVENT_ISSUE_NUMBER, and EVENT_COMMENT_ID respectively.

2. **script-injection (Evaluate review lock, line 162)**: Moved `${{ steps.review-lock.outputs.cache-matched-key }}` out of the run: shell script into the step's env: block as CACHE_MATCHED_KEY.

3. **github-env-injection (Resolve PR number and comment ID, lines 104/112)**: Added `printf '%s' "$VAR" | tr -d '\n\r'` sanitization before writing pr-number and comment-id to $GITHUB_OUTPUT.

4. **github-env-injection (Resolve GitHub token, lines 131/134)**: Added `printf '%s' "$VAR" | tr -d '\n\r'` sanitization before writing token to $GITHUB_OUTPUT in both branches.

5. **github-env-injection (Build review context, line 285)**: Replaced the static `PROMPT_EOF` heredoc delimiter with a randomly generated one (`PROMPT_EOF_$(openssl rand -hex 16)`) so that caller-controlled content in EXTRA_PROMPT cannot prematurely terminate the heredoc and inject arbitrary GITHUB_OUTPUT entries.

### Iteration 2

**Fixes applied:** github-env-injection

**Notes:**

Fixed the github-env-injection vulnerability in the 'Post clean summary' step of review-pr/action.yml (line 670). The REVIEW_URL value (derived from $REPOSITORY which comes from github.repository) is now sanitized before being written to $GITHUB_OUTPUT. Added `safe_review_url=$(printf '%s' "$REVIEW_URL" | tr -d '\n\r')` and changed the echo to use the sanitized variable: `echo "review-url=$safe_review_url" >> "$GITHUB_OUTPUT"`. This prevents newline injection attacks where a malicious repository name could inject additional key-value pairs into $GITHUB_OUTPUT.

