# lang/go — mission and scope

Source of truth for what this adversary is *for*.

- **Package:** `go`
- **Factory routing:** human PR comments are attributed to this adversary only when they match **In scope**.
- **Languages / surfaces:** Go

## Mission

Review Go for TLS bypasses, shell commands, and unsafe filesystem permissions.

## In scope (fair miss if humans raised it and we did not)

- TLS verification disabled
- Shell command injection patterns in Go
- Unsafe filesystem permissions

## Out of scope (not a miss for this adversary)

- Broad eng judgment
- Concurrency lifecycle (go-concurrency)
- Full security program (go-security)

## Factory grading rule

- **In scope + human raised it + this adversary did not surface it** → real miss → suggested issue for **this** package
- **Out of scope** → do not grade as a miss for this adversary
- **Better fit for another adversary** → route there; do not double-count as a miss here
- **Unclear** → prefer out-of-scope for grading
