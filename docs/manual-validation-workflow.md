# Manual Validation Workflow

Validation-ready findings are source-derived leads. They require manual confirmation by an authorized tester before they can be treated as confirmed issues.

## Required Conditions

- Written authorization and approved scope.
- Staging, lab, or internal beta environment.
- Approved test identities and test data.
- Manual operation through browser, Burp, Postman, or equivalent approved tooling.

## Evidence To Collect

- Source file, line, route, and handler references.
- Manual request and response pair from the approved environment.
- Timestamps and reviewer notes.
- Relevant application log or audit record.
- False positive checks showing whether framework middleware, service guards, model policies, or tenant constraints already enforce the control.

## Safety Notes

- Do not automate validation steps.
- Do not test targets outside approved scope.
- Do not access accounts, files, or records outside approved test data.
- Do not create destructive data changes.

## Status Changes

The analyzer can produce `logic_analyzed` and `validation_ready`. A tester may mark a finding as `manually_confirmed`, `false_positive`, or `accepted_risk` only after collecting and reviewing manual evidence.
