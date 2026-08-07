# Go adversary (`lang/go`)

**Go language pack.** Running this package expands composition (`uses` in
`adversary.yaml`) to the full Go specialist suite, then runs this package’s own
generic checks (TLS bypass, shell execution, world-writable paths).

```sh
# CLI with composition support (adversarylabs/adversary uses expand):
adversary run lang/go --path /path/to/repo
# or local checkout:
adversary run . --path /path/to/repo
```

Members (via `uses`): `go/cli`, `go/concurrency`, `go/database`, `go/http`,
`go/modules`, `go/observability`, `go/performance`, `go/project`, `go/security`,
`go/testing`.

Use `--no-compose` to run only this package’s rules.

> Architecture status: this package still carries legacy generic Go smells that
> should move into bounded specialists (e.g. Go Security). Composition is the
> product shape: **meta pack = entrypoint + specialists**.

## Checks (this package only)

- **Go TLS client skips certificate verification:** Keep certificate verification enabled.
- **Go executes through a shell:** Invoke the target binary directly.
- **Go creates a world-writable path:** Use owner-scoped filesystem permissions.

## Development

```sh
npm ci
npm test
adversary validate .
adversary pack --check .
```

## Automatic detection

`adversary auto` selects `lang/go` when changes include `**/*.go`, plus the other
domain-specific patterns declared in `adversary.yaml`. Unrelated changes do not
select it. (Auto mode does not expand `uses` yet; use an explicit
`adversary run lang/go` for the full suite.)
