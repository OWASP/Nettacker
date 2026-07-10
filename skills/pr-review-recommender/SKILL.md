---
name: pr-review-recommender
description: Structured pull request review workflow that evaluates correctness, security, tests, maintainability, documentation, and release risk, then gives a clear merge recommendation with justification. Use when asked to review a PR, assess whether a PR should be merged, write PR review comments, classify review findings, or provide merge/no-merge guidance.
---

# PR Review Recommender

## Overview

Use this skill to perform a comprehensive pull request review and end with an explicit, justified merge recommendation. Keep the review evidence-based: cite changed files, test results, CI status, and any assumptions or limitations.

## Review Workflow

1. Establish the PR intent.
   - Read the PR description, linked issue, commit messages, and changed-file summary.
   - Identify the promised behavior change, user impact, compatibility expectations, and out-of-scope work.
   - Flag mismatches between the stated intent and implementation.

2. Inspect the diff for correctness.
   - Review changed code paths, affected callers, defaults, error handling, edge cases, and backward compatibility.
   - Look for incomplete refactors, dead code, duplicated logic, concurrency issues, async mistakes, and surprising behavior changes.
   - Trace user-facing flows instead of only reading isolated hunks.

3. Review security and data-safety implications.
   - Check for exposed secrets, unsafe logging, weak authz/authn, injection, shell execution, path traversal, SSRF, unsafe deserialization, and dependency risk.
   - Verify user-controlled input is validated and errors are safe.
   - Treat security-sensitive behavior changes as requiring stronger tests and clearer justification.

4. Review tests and validation evidence.
   - Confirm tests cover the happy path, meaningful edge cases, regression cases, and failure modes.
   - Prefer tests that would fail without the PR.
   - If tests cannot be run, state that explicitly and include the resulting risk in the recommendation.

5. Review maintainability.
   - Evaluate naming, structure, type usage, duplication, public API docs, function size, and consistency with local style.
   - Prefer focused PRs; flag unrelated rewrites or changes that make future maintenance harder.

6. Review dependencies, packaging, migrations, and docs when relevant.
   - For dependency changes, check necessity, version constraints, license/maintenance signals, and lockfile consistency.
   - For behavior changes, check user docs, CLI/API help, migration notes, release notes, screenshots, or examples.

7. Classify findings by severity.
   - **Blocker**: must fix before merge; examples include security issues, data loss, broken core behavior, failing required tests, or incomplete implementation.
   - **Major**: should usually fix before merge; examples include missing important tests, likely user-facing edge-case bugs, or poor error handling in important paths.
   - **Minor**: can be fixed before or shortly after merge; examples include small documentation, naming, or cleanup issues.
   - **Nit**: optional polish.

8. Make a merge recommendation.
   - Use exactly one of: **Merge**, **Merge after minor changes**, **Do not merge yet**, or **Request redesign**.
   - Justify the recommendation using the highest-severity unresolved findings, test evidence, and risk assessment.

## Output Template

```markdown
## Summary

Briefly describe what the PR changes and whether the implementation matches the stated intent.

## Review scope

Files/areas reviewed:
- `path/to/file`

Evidence checked:
- Diff inspection
- Tests reviewed
- CI status reviewed
- Local commands run, if any

## Findings

### <Severity>: <Short finding title>

Explain the issue, impact, and why it matters.

Suggested fix:
Describe the concrete fix or mitigation.

## Positive notes

- Mention well-designed, well-tested, or low-risk parts of the PR.

## Test evidence

- `<command or CI check>`: pass/fail/not run, with reason when not run.

## Merge recommendation

**Recommendation: <Merge | Merge after minor changes | Do not merge yet | Request redesign>.**

Justification:
Explain the decision in terms of correctness, risk, tests, and unresolved findings.
```

## Recommendation Rules

- Recommend **Merge** only when implementation is correct, risk is low, and no blocker or major findings remain.
- Recommend **Merge after minor changes** when the PR is sound and only minor/nit issues remain.
- Recommend **Do not merge yet** when blockers or major issues remain, required tests are missing, or validation is insufficient for the risk level.
- Recommend **Request redesign** when the approach is fundamentally misaligned, too broad, or likely to create long-term architectural or maintenance problems.

## Review Tone

Be direct, specific, and actionable. Avoid vague comments such as “this seems wrong”; explain the impact and propose a fix. Separate facts from assumptions. If evidence is unavailable, say what was not checked and how that affects confidence.
