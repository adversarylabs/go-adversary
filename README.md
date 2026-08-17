# Go adversary

Go language pack — runs the full Go specialist suite (concurrency, security, http, modules, …) plus this package’s own TLS/shell/permissions checks.

## Goals

The adversary is designed to produce a small number of high-confidence,
actionable findings grounded in concrete repository evidence. Its review should
be deterministic where possible, explicit about impact, and quiet when the
available evidence does not justify a finding.

## Scope

It provides the transitional generic Go review layer and composes the specialist Go adversaries while retaining a small compatibility rule set.

The complete detector or review inventory is maintained in
[CHECKS.md](CHECKS.md).

## Boundaries

It is a transitional composition layer; new Go domain rules belong in the bounded `go/*` specialist that owns them.
