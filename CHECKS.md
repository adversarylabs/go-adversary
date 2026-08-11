# Checks — what go detects

This file is the **public audit list** of detectors for the **go** adversary — the general-purpose Go entry point. It ships a small set of highest-confidence, cross-cutting Go security rules. The specialized `go/*` adversaries (`go/security`, `go/http`, `go/database`, `go/concurrency`, `go/cli`, `go/modules`, `go-testing`, `go-observability`, `go-performance`, `go-project`) go deeper per domain; when one of those is also installed, its overlapping rule takes precedence and this adversary's duplicate stays quiet.

Runtime source of truth: [`src/spec.ts`](src/spec.ts) / [`src/rules.ts`](src/rules.ts).

**Scope:** `*.go` excluding vendored trees and `_test.go` (except where noted).

**Precision stance:** Only rules that are unambiguous from the AST fire here. Anything needing taint tracking, framework modeling, or repo context belongs to the specialized adversaries.

Public grounding: gosec rule families (G204/G304/G306/G402), Go security best practices, and the shared `go/security` catalog definitions (these rules are the same detectors, curated down).

---

## Critical

### `go.shell-command`

| | |
| --- | --- |
| **What** | Shell invoked with a constructed command string |
| **Why** | `exec.Command("sh", "-c", s)` with any non-constant `s` is command injection waiting for input; the shell layer adds nothing when the target binary can be invoked directly |
| **Looks for** | `exec.Command`/`CommandContext` with `"sh"`/`"bash"` + `-c` where the command argument is built via concat/`fmt.Sprintf`/variables |
| **Stays quiet when** | Fully constant command strings (still note the pattern at low); direct argv invocation (`exec.Command("git", "status")`) |
| **Public examples** | gosec G204; OWASP command injection |
| **Remediation** | Invoke the target binary directly with an argument list — no shell in between |

---

## High

### `go.tls-insecure`

| | |
| --- | --- |
| **What** | TLS certificate verification disabled |
| **Why** | `tls.Config{InsecureSkipVerify: true}` converts every connection into a MITM opportunity; it always outlives the debugging session that motivated it |
| **Looks for** | `InsecureSkipVerify: true` in composite literals outside `_test.go` |
| **Stays quiet when** | `_test.go` and clearly test-scoped helper files; custom `VerifyPeerCertificate`/`VerifyConnection` implementing pinning alongside the flag (downgrade to medium with a note — this is the one legitimate pattern) |
| **Public examples** | gosec G402; CodeQL go/disabled-certificate-check |
| **Remediation** | Keep certificate verification enabled; fix trust properly (custom RootCAs) instead of skipping |

---

## Medium

### `go.world-writable`

| | |
| --- | --- |
| **What** | File or directory creation requests overly broad permissions |
| **Why** | `0666`/`0777` and `ModePerm` request every relevant group and world permission bit before umask; permissive deployments can expose tampering primitives |
| **Looks for** | Production creation/chmod calls with broad numeric modes; `os.Mkdir(All)` with direct `os.ModePerm`/`fs.ModePerm`, including wrapped or ORed expressions |
| **Stays quiet when** | Explicit narrower modes; `ModePerm` used as a mask or inspection value, passed to non-directory APIs, or used in `_test.go` files |
| **Public examples** | gosec G306/G302 |
| **Remediation** | Choose explicit least-privilege permissions (`0600`/`0644` files, `0700`/`0755` dirs) instead of relying on the process umask |

---

## Deferred candidates (not yet in `src/spec.ts`)

Next rules to promote once fixtures exist, in order — both are zero-taint AST rules matching this adversary's precision bar:

- `go.sql-concat` — `fmt.Sprintf`/`+` built SQL reaching `Query`/`Exec` (shared definition: `go-security.sql.string-concat`), critical.
- `go.weak-random-token` — `math/rand` feeding token/secret/session identifiers (shared definition: `go-security.crypto.math-rand`), high.

---

## Out of scope (owned elsewhere)

| Concern | Owner |
| --- | --- |
| Full Go security depth (SQLi taint, JWT, SSRF, zip-slip, nonce reuse…) | `go/security` |
| HTTP server/client hardening | `go/http` |
| Database access patterns | `go/database` |
| Concurrency correctness | `go/concurrency` |
| CLI behavior, module graph, tests, observability, performance, repo hygiene | respective `go/*` adversaries |
| Committed secrets | `security/secrets` |
