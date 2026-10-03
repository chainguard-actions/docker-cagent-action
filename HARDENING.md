<!-- markdownlint-disable -->

# Hardening Report: docker--cagent-action/v1.5.5

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **docker--cagent-action/v1.5.5** was hardened automatically. 6 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Rule (a): The 'Resolve PR number and comment ID' run: block directly interpolates GitHub Actions expressions inside shell commands. Specifically: `PR_NUMBER="${{ github.event.pull_request.number }}"`, `PR_NUMBER="${{ github.event.issue.number }}"`, and `COMMENT_ID="${{ github.event.comment.id }}"` are all interpolated directly into the shell script before the shell ever sees them. These values are attacker-controllable (via PR/issue/comment events) and can contain shell metacharacters that execute arbitrary commands.

Locations:

- `review-pr/action.yml:93`
- `review-pr/action.yml:96`
- `review-pr/action.yml:103`

### script-injection (severity: high)

Rule (a): The 'Evaluate review lock' run: block directly interpolates `${{ steps.review-lock.outputs.cache-matched-key }}` inside a shell `if [ -n "..."]` test. Step outputs are workflow-controllable and this expression is substituted into the shell command string before execution, enabling shell metacharacter injection.

Locations:

- `review-pr/action.yml:140`

### github-env-injection (severity: high)

The 'Resolve PR number and comment ID' step writes untrusted values to $GITHUB_OUTPUT without sanitization. $PR_NUMBER is derived from inputs.pr-number, ${{ github.event.pull_request.number }}, or ${{ github.event.issue.number }} (all attacker-controllable). $COMMENT_ID is derived from inputs.comment-id or ${{ github.event.comment.id }}. Both are written via `echo "pr-number=$PR_NUMBER" >> $GITHUB_OUTPUT` and `echo "comment-id=$COMMENT_ID" >> $GITHUB_OUTPUT` without the required `printf '%s' ... | tr -d '\n\r'` sanitization step, allowing newline injection into the output file.

Locations:

- `review-pr/action.yml:99`
- `review-pr/action.yml:104`

### github-env-injection (severity: high)

The 'Resolve GitHub token' step writes `$EXPLICIT_TOKEN` (sourced from `inputs.github-token`, an untrusted composite-action input) to $GITHUB_OUTPUT via `echo "token=$EXPLICIT_TOKEN" >> $GITHUB_OUTPUT` without the required `printf '%s' ... | tr -d '\n\r'` sanitization. A caller-supplied token value containing newlines could inject arbitrary key=value pairs into the GitHub output file.

Locations:

- `review-pr/action.yml:112`

### github-env-injection (severity: high)

The 'Collect pending feedback' step writes the $COMBINED variable (built from downloaded artifact data, which is externally controlled) to $GITHUB_OUTPUT using a heredoc with delimiter FEEDBACK_EOF: `echo "prompt<<FEEDBACK_EOF"` / `echo "$COMBINED"` / `echo "FEEDBACK_EOF"`. If the artifact data contains the string FEEDBACK_EOF on its own line, the heredoc terminates early and subsequent lines are interpreted as additional GITHUB_OUTPUT key=value pairs, enabling environment injection. No sanitization is applied.

Locations:

- `review-pr/action.yml:663`

### github-env-injection (severity: high)

The 'Build review context' step writes review_context.md (which contains $EXTRA_PROMPT from inputs.additional-prompt, an untrusted input) to $GITHUB_OUTPUT using a heredoc with delimiter PROMPT_EOF: `echo "review_prompt<<PROMPT_EOF"` / `cat review_context.md` / `echo "PROMPT_EOF"`. If inputs.additional-prompt contains the string PROMPT_EOF on its own line, the heredoc terminates early and subsequent content is interpreted as additional GITHUB_OUTPUT entries, enabling environment injection. No sanitization is applied.

Locations:

- `review-pr/action.yml:757`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, github-env-injection

**Notes:**

Fixed all 6 findings in review-pr/action.yml:
1. Script injection (lines 93, 96, 103): Moved github.event.pull_request.number, github.event.issue.number, and github.event.comment.id into env vars (EVENT_PR_NUMBER, EVENT_ISSUE_NUMBER, EVENT_COMMENT_ID) in the 'Resolve PR number and comment ID' step.
2. Script injection (line 140): Moved steps.review-lock.outputs.cache-matched-key into env var CACHE_MATCHED_KEY in the 'Evaluate review lock' step.
3. GitHub env injection (lines 99, 104): Added `printf '%s' "$VAR" | tr -d '\n\r'` sanitization before writing pr-number and comment-id to GITHUB_OUTPUT.
4. GitHub env injection (line 112): Added `printf '%s' "$VAR" | tr -d '\n\r'` sanitization before writing token to GITHUB_OUTPUT in the 'Resolve GitHub token' step.
5. GitHub env injection (line 663): Replaced fixed FEEDBACK_EOF heredoc delimiter with a randomized one using `openssl rand -hex 16` to prevent delimiter collision injection in the 'Collect pending feedback' step.
6. GitHub env injection (line 757): Replaced fixed PROMPT_EOF heredoc delimiter with a randomized one using `openssl rand -hex 16` to prevent delimiter collision injection in the 'Build review context' step.

### Iteration 2

**Fixes applied:** github-env-injection

**Notes:**

Fixed the github-env-injection finding in hardened/action/review-pr/action.yml. In the 'Post clean summary' step, the REPOSITORY variable (sourced from ${{ github.repository }}) was used unsanitized to construct REVIEW_URL before writing it to $GITHUB_OUTPUT. Added sanitization: `SAFE_REPOSITORY=$(printf '%s' "$REPOSITORY" | tr -d '\n\r')` and updated REVIEW_URL to use `$SAFE_REPOSITORY` instead of `$REPOSITORY`. This prevents newline injection attacks via the github.repository context value.

