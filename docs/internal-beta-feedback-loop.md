# Internal Beta Feedback Loop

## Feedback Objective

Collect actionable internal beta feedback for bugfix, UX clarity, documentation, report quality, false positive/false negative handling, and safety regression prevention.

## Feedback Sources

- CLI tester.
- Dashboard tester.
- Report reviewer.
- Safety reviewer.

## Authorized-Only Testing Requirement

Testing must use only authorized lab, sample, internal, staging, or pre-production targets. Stop when authorization, scope, or network behavior is unclear.

## Supported Workflows

- Type 1 Source Code / Folder Project Assessment.
- Type 2 Domain / Website Target Assessment.

## Feedback Categories

- bug
- UX issue
- documentation issue
- false positive
- false negative
- safety concern
- report formatting issue
- CLI issue
- dashboard issue

## Severity

- blocker
- high
- medium
- low
- note

## Triage Rules

- Blocker/high safety issue must be fixed before wider use.
- False positive/false negative must be documented and prioritized.
- UX issue can be grouped into patch release.
- Feature request must be deferred unless safe and approved.

## Fix Rules

- Bugfix allowed.
- Documentation improvement allowed.
- Test improvement allowed.
- Guardrail improvement allowed.
- Offensive feature not allowed.

## Regression Rule

Every bugfix needs pytest. Safety static test must remain green.

## Patch Release Rule

Use `v0.3.1-beta-patch` or similar after accumulated safe fixes.

## Stop Conditions

- Unclear authorization.
- Unclear scope.
- Unexpected network behavior.
- Potential secret exposure.
- Unsafe scan behavior.
- Out-of-scope target.
