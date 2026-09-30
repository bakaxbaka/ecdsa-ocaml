# Signature dataset analysis report

## Scope and data quality

The checked dataset contains 20,449 rows with `ecdsa_valid=true`.  The
duplicate scan found no repeated `(pubkey, r)` pair, so it found no evidence
of ECDSA nonce reuse.  This is a negative result, not proof that every
transaction sighash was independently reconstructed from an external source.

Six rows are `P2SH-P2WSH`, across three transactions.  They must use BIP143
with the inner witness script as `scriptCode`, rather than legacy P2SH hashing
with the redeem script.  They are therefore recorded as
**sighash-unverified** until their raw transactions and prevouts are checked
against an independent Bitcoin implementation.  In particular,
`ecdsa_valid=true` only establishes that the stored digest verifies the stored
signature and public key; it is not an independent proof that the digest was
constructed with the right script routing.

The remaining desired assurance work is an independent sample of P2PKH, P2SH,
and P2WPKH sighashes, plus an independent check of those six nested P2WSH
rows.  These need a raw-transaction/prevout source or offline reference bundle.

## Bit-bias result

The 20,449 verified `r` values contain 5,234,944 bits.  The measured fraction
of one bits is 0.5001447962.  The monobit and runs checks previously computed
for this dataset are both ordinary null results (z = 0.66 and z = 0.68,
respectively).  Per-position counts range from 10,018 to 10,398, versus an
expectation of 10,224.5 and a binomial standard deviation of approximately
71.5; extrema of this size are unsurprising among 256 positions.

The per-position statistic is 118.135458946648.  The previous script compared
that value directly with `chi-square(256)`, which is incorrect for Bernoulli
bit counts.  If `O_i ~ Binomial(n, 0.5)`, each term

```
(O_i - n/2)^2 / (n/2)
```

has asymptotic mean 0.5, because `Var(O_i) = n/4`.  The sum consequently has
mean 128 and standard deviation about 11.3.  Equivalently, twice the reported
statistic is approximately `chi-square(256)`.  The observed statistic is only
about -0.87 standard deviations from its null mean (two-sided normal
approximation about 0.38), so there is no evidence of bit bias.

`tools/octave/bit_bias.m` now makes that factor-of-two correction, reports both
tails of the corrected reference, and identifies columns by header.  The last
change lets it process both this repository's historical nine-column CSV and
the current ten-column `dump_rsz` output.
