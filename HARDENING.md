<!-- markdownlint-disable -->

# Hardening Report: docker--cagent-action/v1.5.4

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **docker--cagent-action/v1.5.4** was hardened automatically. 4 finding(s) were identified and resolved across 4 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): The 'Resolve PR number and comment ID' run: block in review-pr/action.yml directly interpolates ${{ github.event.pull_request.number }}, ${{ github.event.issue.number }}, and ${{ github.event.comment.id }} inside shell commands. These github context values are attacker-controlled (e.g. via a crafted PR title or comment) and are substituted into the shell script before execution, enabling command injection. Offending lines:
  PR_NUMBER="${{ github.event.pull_request.number }}"
  PR_NUMBER="${{ github.event.issue.number }}"
  COMMENT_ID="${{ github.event.comment.id }}"

Locations:

- `review-pr/action.yml:95`
- `review-pr/action.yml:98`
- `review-pr/action.yml:110`

### script-injection (severity: high)

Sub-rule (a): The 'Evaluate review lock' run: block in review-pr/action.yml directly interpolates ${{ steps.review-lock.outputs.cache-matched-key }} inside a shell test expression. Step outputs are workflow-controllable and flow through YAML template substitution before the shell sees them, enabling command injection. Offending line:
  if [ -n "${{ steps.review-lock.outputs.cache-matched-key }}" ]; then

Locations:

- `review-pr/action.yml:161`

### github-env-injection (severity: high)

The 'Resolve GitHub token' run: block writes $EXPLICIT_TOKEN (sourced from inputs.github-token via env:) and $DEFAULT_TOKEN (sourced from github.token via env:) to $GITHUB_OUTPUT without the required sanitization step (printf '%s' ... | tr -d '\n\r'). An attacker-controlled github-token input containing newlines could inject arbitrary key=value pairs into the output file.
  echo "token=$EXPLICIT_TOKEN" >> $GITHUB_OUTPUT
  echo "token=$DEFAULT_TOKEN" >> $GITHUB_OUTPUT

Locations:

- `review-pr/action.yml:130`
- `review-pr/action.yml:133`

### github-env-injection (severity: high)

The 'Build review context' run: block writes $EXTRA_PROMPT (sourced from inputs.additional-prompt via env:) into review_context.md and then pipes the entire file into $GITHUB_OUTPUT via a heredoc. An attacker-controlled additional-prompt input containing newlines (e.g. 'PROMPT_EOF\nmalicious=value') could inject arbitrary key=value pairs or escape the heredoc delimiter, corrupting the output file.
  echo "$EXTRA_PROMPT" >> review_context.md
  { echo "review_prompt<<PROMPT_EOF"; cat review_context.md; echo "PROMPT_EOF"; } >> $GITHUB_OUTPUT

Locations:

- `review-pr/action.yml:490`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, github-env-injection

**Notes:**

Fixed all four security findings in hardened/action/review-pr/action.yml:

1. Script injection (Resolve PR number and comment ID step): Moved github.event.pull_request.number, github.event.issue.number, and github.event.comment.id from inline ${{ }} interpolation in shell into the step's env: block as EVENT_PR_NUMBER, EVENT_ISSUE_NUMBER, and EVENT_COMMENT_ID.

2. Script injection (Evaluate review lock step): Moved steps.review-lock.outputs.cache-matched-key from inline ${{ }} interpolation in shell test expression into the step's env: block as CACHE_MATCHED_KEY.

3. GitHub env injection (Resolve GitHub token step): Added sanitization with `printf '%s' "$TOKEN" | tr -d '\n\r'` before writing token values to $GITHUB_OUTPUT to prevent newline injection.

4. GitHub env injection (Build review context step): Replaced the static heredoc delimiter PROMPT_EOF with a randomly generated delimiter using `openssl rand -hex 16` to prevent attacker-controlled additional-prompt content from escaping the heredoc and injecting arbitrary key=value pairs into $GITHUB_OUTPUT.

### Iteration 2

**Fixes applied:** github-env-injection

**Notes:**

Fixed the 'Resolve PR number and comment ID' step in review-pr/action.yml by adding sanitization before writing to $GITHUB_OUTPUT:
1. Added `safe_pr_number=$(printf '%s' "$PR_NUMBER" | tr -d '\n\r')` and changed the echo to use `$safe_pr_number` instead of `$PR_NUMBER`.
2. Added `safe_comment_id=$(printf '%s' "$COMMENT_ID" | tr -d '\n\r')` and changed the echo to use `$safe_comment_id` instead of `$COMMENT_ID`.
This matches the sanitization pattern already used in the 'Resolve GitHub token' step in the same file.

### Iteration 3

**Fixes applied:** github-env-injection, github-env-injection

**Notes:**

Fixed two github-env-injection findings in hardened/action/review-pr/action.yml:

1. 'Build review context' step (line ~762): Added `SAFE_EXTRA_PROMPT=$(printf '%s' "$EXTRA_PROMPT" | tr -d '\n\r')` before appending the additional-prompt input to review_context.md. The sanitized variable replaces the raw `$EXTRA_PROMPT` in the heredoc, ensuring newlines are stripped from the untrusted input before it reaches $GITHUB_OUTPUT.

2. 'Post clean summary' step (line ~855): Added sanitization for `$REPOSITORY` (github.repository) and `$PR_NUMBER` using `printf '%s' ... | tr -d '\n\r'`, constructed REVIEW_URL from the sanitized values, then applied a final sanitization pass before writing `review-url=$safe_review_url` to $GITHUB_OUTPUT.

### Iteration 4

**Fixes applied:** github-env-injection

**Notes:**

Fixed heredoc injection vulnerability in the 'Collect pending feedback' step of review-pr/action.yml. The fixed delimiter 'FEEDBACK_EOF' was replaced with a randomly generated UUID-based delimiter 'FEEDBACK_$(uuidgen | tr -d "-")'. Since the delimiter is generated at runtime using a cryptographically random UUID, an attacker who controls artifact content (FB_PATH, FB_LINE, FB_BODY from feedback.json) cannot predict the delimiter and therefore cannot craft a line that matches it to escape the heredoc and inject arbitrary key=value pairs into $GITHUB_OUTPUT.

