# Go adversary

Reviews Go for TLS bypasses, shell commands, and unsafe filesystem permissions.

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
