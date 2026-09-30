# crypto-workbench

Reproducible cryptography research workstation + Bitcoin transaction-forensics study
of the public mainnet address `17GGGHWtyi7e1rxnEpcKpE7fHq1UZBguAb`.

## Read this first
| document | contents |
|---|---|
| `SETUP_REPORT.md` | environment, versions, fixes, exact reproduction commands |
| `TARGET_REPORT.md` | data acquisition, validation, reconciliation, anomalies |
| `TRANSACTION_CATALOG.md` | 5,078-tx catalog: summary, all 29 spenders, per-year stats |
| `SIGNATURE_ANALYSIS.md` | 17-part statistical analysis of 874 target signatures (+figures) |
| `benchmark_results.md` | Python/PARI/Octave/Rust benchmarks + parallelism policy |
| `test_results.md` | 40 vector checks + 72 cross-language checks + pipeline verification |
| `chaindata/README.md` | persisted data artifacts mirror |

## Reproduce
`bash scripts/setup_env.sh` (installs, verifies, builds). Data pipeline order is
listed at the bottom of that script; every step caches and is idempotent.

## Security
Public blockchain data only. No private keys derived, stored, or transmitted;
no credentials handled. Detection-only research (duplicate-r screening etc.).
