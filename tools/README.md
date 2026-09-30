# ecdsa-ocaml Tooling

This directory contains governance and verification scripts for the ecdsa-ocaml project.

## Scripts

### `check-layering.ps1` / `check-layering.sh`

Verifies that the project respects the required layering constraints.

**Layering hierarchy** (dependencies flow downward only):

```
application/
    ↓
storage/
    ↓
analysis/
    ↓
bitcoin/
    ↓
crypto/
    ↓
common/
```

**Usage** (PowerShell):

```powershell
.\tools\check-layering.ps1
```

**Usage** (Bash):

```bash
./tools/check-layering.sh
```

**Behavior**:

- Scans all `dune` files in `lib/` and `bin/`
- Extracts library dependencies from `(libraries ...)` clauses
- Checks that cross-layer dependencies flow downward only
- Allows in-layer dependencies (modules within a layer can depend on each other)
- Skips external dependencies (zarith, digestif, alcotest, etc.)

**Exit codes**:

- `0` — Layering check passed
- `1` — Layering violations detected

**When to run**:

- Before submitting a PR (local verification)
- Automatically in CI (GitHub Actions)
- After adding a new dune file or changing dependencies

**Example**: If `bitcoin/` tries to depend on a library in `analysis/`, the check fails:

```
ERROR: lib\bitcoin\dune
  bitcoin depends on analysis_sig (from analysis)
  Violation: cannot depend upward
```

## CI Integration

The layering check runs in `.github/workflows/ci.yml` after each commit. Violations block merge.

See `.github/CONTRIBUTING.md` for full CI verification workflow.

## Future Tools

- `check-provenance.ps1` — Verify test vector provenance metadata (Phase 1)
- `check-secrets.ps1` — Detect accidental secret exposure in commits (Phase 2)
- `benchmark-runner.ps1` — Performance regression detection (Phase 3)

---

**Status**: Phase 0, Task #5  
**Last Updated**: 2026-09-22
