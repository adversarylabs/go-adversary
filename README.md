# Go adversary

Reviews Go for TLS bypasses, shell commands, and unsafe filesystem permissions.

> Architecture status: this is the legacy generic Go scanner. Its evidence should move into the bounded Go Security reviewer, while repository discovery, reads, search, and semantic analysis move into SDK/runtime ReviewContext capabilities. The cross-catalog capability audit lives in [ReviewContext capability discovery](https://github.com/adversarylabs/go-concurrency-adversary/blob/main/docs/review-context-capabilities.md).

## Checks

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

`adversary auto` selects the go adversary when changes include `**/*.go`, plus the other domain-specific patterns declared in `adversary.yaml`. Unrelated changes do not select it.
