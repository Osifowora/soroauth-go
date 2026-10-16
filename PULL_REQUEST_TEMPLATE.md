# Pull Request Summary

## Description

This PR implements comprehensive verification and fuzz testing improvements for
the Soroban authorization entry verification flow. The changes address contract
node verdict precedence, expand fuzz testing coverage, and improve CI/CD
pipelines.

## Changes

### 1. verify.go - Contract node verdict precedence

- Reordered verification logic so that contract-address checks happen **before**
  unsigned node checks
- This ensures contract-address nodes (C… addresses) are always reported as
  `cannot_check`, even when they carry Void or empty-vector signatures that
  would be considered "unsigned" on account nodes
- Prevents the library from incorrectly claiming a contract node is "simply
  unfilled" when a placeholder may be meaningful to the contract's
  `__check_auth`

### 2. verify_test.go - New test and fuzz target

- Added `TestVerifyEntryCannotCheckAnUnsignedContractNode` test verifying that
  contract nodes are `cannot_check` regardless of signature state (void, empty
  vector, or valid signature)
- Added `FuzzVerifyEntry` fuzz test that validates invariants from
  `docs/verification-limits.md`:
  - Never reports `verified` for signatures crypto/ed25519 rejects
  - Invalid verdicts correspond to ed25519 rejects
  - Contract nodes are always `cannot_check`, never `verified`
  - Malformed/truncated/wrong-type signatures produce verdicts, never panics
- Added `independentPayload` helper for standalone payload reconstruction
- Added `corruptSignatureShapes` helper generating malformed signature inputs

### 3. cmd/gencorpus/main.go - Fuzz target registration

- Added `FuzzVerifyEntry` to the list of fuzz targets
- Added `signed_entry_xdr` vector field for pair corpus drift checking
- Added `FuzzDiffEntries` pair target support
- Updated `fuzzOperation` map to map `FuzzVerifyEntry` to `preimage`

### 4. .github/workflows/fuzz.yml - Fuzz CI configuration

- Added `FuzzVerifyEntry` fuzz target with corpus
  `testdata/fuzz/FuzzVerifyEntry`
- Added `FuzzDiffEntries` fuzz target with corpus
  `testdata/fuzz/FuzzDiffEntries`

### 5. .github/workflows/ci-go.yml - CI fuzz test invocations

- Added fuzz verification for `FuzzVerifyEntry` (30s timeout)
- Added fuzz verification for `FuzzDiffEntries` (30s timeout)

## Closes

- Closes #15
- Closes #16
- Closes #17
- Closes #18

## Additional Notes

- All existing tests pass successfully
- The fuzz targets use golden vectors from `cmd/gencorpus` with corrupted
  signature shapes as additional seeds
- The `FuzzVerifyEntry` target independently re-verifies `verified` verdicts
  using `crypto/ed25519.Verify` to prevent false positives
