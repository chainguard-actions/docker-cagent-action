<!-- markdownlint-disable -->

# Hardening Report: docker--cagent-action--review-pr/v1.5.5

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **docker--cagent-action--review-pr/v1.5.5** was hardened automatically. 5 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): In the 'Resolve PR number and comment ID' step, three GitHub Actions expressions are directly interpolated inside the run: shell script without going through an env: variable: `PR_NUMBER="${{ github.event.pull_request.number }}"`, `PR_NUMBER="${{ github.event.issue.number }}"`, and `COMMENT_ID="${{ github.event.comment.id }}"`. These values are attacker-controlled (a malicious PR/issue/comment can supply arbitrary content) and are substituted into the shell before the shell parses the script, enabling command injection.

Locations:

- `action.yml:96`
- `action.yml:99`
- `action.yml:105`

### script-injection (severity: high)

Sub-rule (a): In the 'Evaluate review lock' step, `${{ steps.review-lock.outputs.cache-matched-key }}` is directly interpolated inside the run: shell script: `if [ -n "${{ steps.review-lock.outputs.cache-matched-key }}" ]; then`. Step outputs are workflow-controllable and must not be interpolated directly into shell commands.

Locations:

- `action.yml:131`

### github-env-injection (severity: high)

In the 'Resolve PR number and comment ID' step, PR_NUMBER (derived from ${{ github.event.pull_request.number }} or ${{ github.event.issue.number }}) and COMMENT_ID (derived from ${{ github.event.comment.id }}) are written to $GITHUB_OUTPUT without the required sanitization step (printf '%s' ... | tr -d '\n\r'). An attacker can inject newlines into these values to poison subsequent steps that read from GITHUB_OUTPUT. Offending lines: `echo "pr-number=$PR_NUMBER" >> $GITHUB_OUTPUT` and `echo "comment-id=$COMMENT_ID" >> $GITHUB_OUTPUT`.

Locations:

- `action.yml:103`
- `action.yml:107`

### github-env-injection (severity: high)

In the 'Resolve GitHub token' step, EXPLICIT_TOKEN (sourced from inputs.github-token, an untrusted composite-action input) is written to $GITHUB_OUTPUT without sanitization: `echo "token=$EXPLICIT_TOKEN" >> $GITHUB_OUTPUT`. A caller-supplied token value containing newlines could inject additional key=value pairs into GITHUB_OUTPUT.

Locations:

- `action.yml:119`

### github-env-injection (severity: high)

In the 'Build review context' step, EXTRA_PROMPT (sourced from inputs.additional-prompt) is appended to review_context.md and then the entire file is written to $GITHUB_OUTPUT via a heredoc (`cat review_context.md >> $GITHUB_OUTPUT`). If EXTRA_PROMPT contains the heredoc delimiter string 'PROMPT_EOF' on its own line, it will prematurely terminate the heredoc and allow injection of arbitrary key=value pairs into GITHUB_OUTPUT. No sanitization is applied.

Locations:

- `action.yml:222`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, github-env-injection

**Notes:**

Fixed all 5 findings in action.yml:
1. Script injection (Resolve PR number step): Moved github.event.pull_request.number, github.event.issue.number, and github.event.comment.id from inline shell interpolation into env: vars (EVENT_PR_NUMBER, EVENT_ISSUE_NUMBER, EVENT_COMMENT_ID).
2. Script injection (Evaluate review lock step): Moved steps.review-lock.outputs.cache-matched-key from inline shell interpolation into an env: var (CACHE_MATCHED_KEY).
3. GitHub env injection (Resolve PR number step): Added printf '%s' ... | tr -d '\n\r' sanitization before writing pr-number and comment-id to GITHUB_OUTPUT.
4. GitHub env injection (Resolve GitHub token step): Added printf '%s' ... | tr -d '\n\r' sanitization before writing token to GITHUB_OUTPUT.
5. GitHub env injection (Build review context step): Replaced fixed heredoc delimiter 'PROMPT_EOF' with a random delimiter (PROMPT_EOF_$(openssl rand -hex 16)) to prevent injection via user-controlled additional-prompt content.

