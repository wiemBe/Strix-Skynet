# Bundled Strix engine

| | |
|---|---|
| Package | `strix-agent` 1.7.0 (official wheel, unmodified) |
| Upstream | https://github.com/usestrix/strix |
| License | Apache-2.0, see [LICENSE](LICENSE) |
| Platform | macOS on Apple silicon (`py3-none-macosx_11_0_arm64`; contains the native `strix-tui`) |
| SHA-256 | see [SHA256SUMS](SHA256SUMS), checked before every install |

`requirements.lock` is the exact dependency set of the runtime that passed Skynet's tests and two real local
scans on 2026-11-15. `scripts/setup_strix.sh` (run automatically by `./run.sh`) installs both into
`.strix-runtime/`, which stays out of git.

To move to another Strix version, replace the wheel, regenerate `requirements.lock` and `SHA256SUMS` from a
tested runtime, update `WANT`/`WHEEL` in `scripts/setup_strix.sh` and `SUPPORTED_STRIX` in
`skynet/strix_bridge.py`, then run the test suite (the runtime checks in `tests/runtime/` included).
