# Bundled Strix engine

| | |
|---|---|
| Package | `strix-agent` 1.7.0 (official wheel, unmodified) |
| Upstream | https://github.com/usestrix/strix |
| License | Apache-2.0, see [LICENSE](LICENSE) |
| Platforms | Linux x86_64 (`manylinux_2_17_x86_64`), macOS Apple silicon (`macosx_11_0_arm64`); native `strix-tui` included |
| SHA-256 | see [SHA256SUMS](SHA256SUMS), checked before every install |

`requirements.lock` is the exact dependency set verified on macOS and Red Hat UBI 9 x86_64 / Python 3.12.
The macOS runtime also completed real local scans on 2026-11-15; Linux QA did not start a pentest. `scripts/setup_strix.sh` (run automatically by `./run.sh`) installs both into
`.strix-runtime/`, which stays out of git.

To move to another Strix version, replace the wheel, regenerate `requirements.lock` and `SHA256SUMS` from a
tested runtime, update the version/platform map in `scripts/setup_strix.py` and `SUPPORTED_STRIX` in
`skynet/strix_bridge.py`, then run the test suite (the runtime checks in `tests/runtime/` included).
