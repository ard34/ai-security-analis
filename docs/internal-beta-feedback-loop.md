# Internal Beta Feedback Loop

## Feedback Objective

Collect actionable internal beta feedback while preserving authorized-only, safe-by-default usage. Feedback should improve reliability, documentation, UX clarity, report quality, and safety regression prevention.

## Who Can Test

- Internal security engineers.
- Internal application security reviewers.
- Internal pentesters operating under written authorization.

## Authorized-Only Testing Requirement

Use only authorized sample, lab, internal, or pre-production targets. Stop if authorization, scope, or network behavior is unclear.

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

## Feedback Severity

- blocker
- high
- medium
- low
- note

## Triage Process

1. Capture feedback with the closest local issue template.
2. Record workflow, version/tag, environment, expected result, actual result, and safety impact.
3. Assign severity.
4. Prioritize safety concerns, data exposure, scope issues, and gate bypass reports.
5. Link any reproduction steps to local-only or authorized test assets.

## Fix Decision Process

- Fix bugfix, docs, UX clarity, report formatting, sample cleanup, and safety regression items during stabilization.
- Defer feature expansion and any offensive capability request.
- Keep all findings potential until manual validation.

## Regression Test Requirement

Every accepted fix requires either a new deterministic local test or an update to an existing test. Run `pytest -q` and safety static tests before accepting a fix.

## Stop Conditions

- unclear authorization
- unclear scope
- unexpected network behavior
- potential secret exposure
- unsafe scan behavior
- out-of-scope target
