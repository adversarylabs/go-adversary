# Go adversary

This repository contains the legacy generic Go adversary.

Do not add new repository walking, Git, file-reading, globbing, search, or parsing responsibilities. The target architecture makes the runtime responsible for prepared review context and the adversary responsible for domain judgment.

The existing TLS, shell execution, and filesystem permission signals should migrate into the bounded Go Security reviewer. Treat the current scanner as transitional.

Keep existing checks deterministic and evidence-backed. Never execute target code. Add focused vulnerable and clean fixtures for every compatibility change. Run `npm test`, `adversary validate .`, and `adversary pack --check .` before release.
