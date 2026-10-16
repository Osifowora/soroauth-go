# What the parity suites prove

"Proven byte-for-byte" is strong evidence and it is not an audit. This page
states exactly what each agreement suite covers, and what none of them rule out.
The honest framing is the same one in
[SECURITY.md](../SECURITY.md#status-of-this-library): agreeing with a reference
implementation and being accepted by a host are not the same thing as having
been audited, and neither rules out a class of bug that more than one
implementation shares.

## What each suite covers

| Suite                                               | It proves                                                                                                                                                                                                                                                                                                                                                                                                                                                           | How to run it                            |
| --------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------- |
| Golden vectors (`testdata/vectors/`)                | soroauth reproduces `@stellar/stellar-sdk@17.1.0` byte for byte: for every vector, the preimage bytes, the payload hash, and the final signed entry are identical. The generator (`testdata/gen/gen.mjs`) refuses to run against any other SDK version, and CI regenerates on every push and fails on drift.                                                                                                                                                        | `make vectors-check`                     |
| Python parity (`testdata/parity-python/`)           | The vectors' preimages and payloads recompute identically under a third, separately maintained implementation (`stellar-sdk==16.1.0` on PyPI, pinned in `requirements.txt`, refused if anything else is installed). This is the suite that can say "no" to a bug the Go library and the JS reference share.                                                                                                                                                         | `make parity`                            |
| Rust parity (`testdata/parity-rust/`)               | The same recomputation against `stellar-xdr =28.0.0` (pinned exactly, `Cargo.lock` committed, `--locked` enforced) — the XDR implementation `rs-soroban-env` itself decodes with. Agreement here is the strongest offline evidence available short of submitting a transaction.                                                                                                                                                                                     | `make parity-rust`                       |
| Rust crate (`bindings/rust/`)                       | The native-crate form of the same claim: the crate decodes with that same `stellar-xdr` pin and replays every golden vector — preimage bytes, payload hash, and signed entry — with byte equality in CI. A binding over the C ABI would be a different project with different risks; this one has no binding layer, and `#![forbid(unsafe_code)]` leaves no `unsafe` to justify. Errors mirror the Go sentinels; verification keeps four verdicts, never a boolean. | `cargo test --locked` in `bindings/rust` |
| Differential fuzzing (`testdata/differential/`)     | Agreement beyond the cases someone wrote down: `cmd/difffuzz` generates a deterministic corpus of random structurally valid entries (every arm, random delegate and sub-invocation depth, both nonce signs, the `int64` edges) and requires Go, JS, and Python to agree on every payload. A divergence is a release blocker.                                                                                                                                        | `make differential`                      |
| Wasm parity (`wasm/parity.mjs`)                     | The browser build emits the same bytes as the native one: every golden vector, every differential corpus case (and its frozen regressions), and every fuzz seed replayed through `wasm/dist/soroauth.wasm` against the bytes the native build produced. A seed the native build refused must be refused too. Note the direction — the wasm core is a thin binding over this same Go code, so this proves the build, not independence.                               | `make wasm-check`                        |
| Live testnet scenarios (`e2e/RESULTS.md`)           | A real host accepted (or, for the rejection scenarios, refused for the asserted reason) transactions carrying these entries. This is the only suite where the Soroban host itself renders a verdict.                                                                                                                                                                                                                                                                | `make e2e`                               |
| Passkey shape vectors (`testdata/vectors/passkey/`) | The P-256 `{public_key, signature}` map is byte-identical to what `smart-account-kit@0.8.0`, a real passkey wallet library, builds — asserted for both the inner map and the library's complete output. Live acceptance of that shape is scenarios J and K, not this suite.                                                                                                                                                                                         | `make vectors-check`                     |

Three behaviors are uniform across the offline suites, by design: cases with no
preimage (today the source-account vectors — arm 0 is authenticated by the
transaction envelope, CAP-46-11) are skipped loudly, named, and counted; a run
that checks nothing exits non-zero, so no suite can pass by doing nothing; and
no suite ever writes to the vectors — a disagreement means an implementation is
wrong, and editing a vector to make a harness pass destroys the evidence (see
[CONTRIBUTING.md](../CONTRIBUTING.md#golden-vectors)).

## Structural boundaries, and where the implementations disagree

The vectors include the structural limits a host enforces, not only the shapes
someone happened to write down (#366): `v2_account_multisig_20_signatures` is
exactly the host's `MAX_ACCOUNT_SIGNATURES = 20` account signatures,
`v2_empty_args` is an empty argument list, `delegates_single_node` is the
shallowest tree, and `delegates_chain_depth_57` is the deepest delegate nesting
the library accepts end to end.

The depth vector records a real disagreement between the two implementations
rather than a shared limit:

- The pinned `@stellar/stellar-sdk` imposes **no policy cap** on delegate
  nesting. Its only bound is the XDR codec's internal recursion guard (1500
  frames), and it will build — and sign — chains of several hundred delegates.
- `DecodeAuthorizationEntry` applies the library's 64-frame XDR bound, and each
  delegate costs roughly two frames, so it refuses a chain of 58 and accepts 57.
- `WithDelegates` applies the `MaxDecodeDepth = 64` traversal bound, which
  accepts a chain of 63 (its guard also visits the empty level below a leaf).

The intersection is 57, which is the vector's recorded depth. The finding is
that a client which trusts the JS SDK to decide "this tree is fine" can build an
entry the Go library then refuses to decode; anything near that boundary should
be validated against the intended library before it is signed.

## What the wasm parity harness replays

`wasm/parity.mjs` replays four corpora through `wasm/dist/soroauth.wasm` and
compares its output, byte for byte, with how the native build responded:

- the golden vectors, whose preimage, payload and signed entry are the bytes the
  native build and `@stellar/stellar-sdk` already agree on;
- the differential fuzzing corpus, whose entries `cmd/difffuzz` generated and
  whose payloads Go, JS and Python all reproduce;
- the regressions frozen from past differential divergences; and
- the fuzz seed corpus, replayed against
  `testdata/wasm-parity/fuzz_expectations.json`.

The fuzz seed corpus has no recorded bytes of its own — a Go fuzz seed is an
input, not a result — so `cmd/gencorpus` records the native result for every
seed in `testdata/wasm-parity/fuzz_expectations.json` in the same run that
writes the seeds. That file is generated, committed and drift-checked with the
seeds it describes, so the two can never name different bytes;
`go run ./cmd/gencorpus` regenerates both. A seed with no recorded expectation
fails the harness rather than being skipped, because a silently unrecorded seed
is a case that stopped being checked.

The wasm core exposes `preimage` and `payload` only. Entry-shaped seeds are
replayed through `preimage`; `FuzzPayload`'s raw bytes are replayed through
`payload`. That means the `FuzzInspect`, `FuzzDecodeAuthorizationEntry`,
`FuzzValidateDelegateOrder` and `FuzzVerifyEntry` seeds are exercised through
the shared entry decoder and preimage path, not through those four functions:
the harness proves the wasm build decodes and hashes them identically, and does
not prove `Inspect`, the delegate-order check or `VerifyEntry` behave the same
under wasm, because none is part of the wasm surface.

`FuzzDiffEntries` is not replayed at all. Its seeds carry two entries each and
the wasm core has no `DiffEntries` surface, so the expectations file lists the
target under `non_replayed_targets` and the harness counts its seeds as skipped
with that reason. The list is written by `cmd/gencorpus` rather than hardcoded
in the harness, so the two cannot disagree about which target it names.

For the same reason the golden vector signed by a classic-account multisig
(`v2_account_multisig_20_signatures`) is reported as skipped: the binding's
signing entry point takes one seed, so it cannot assemble a multi-signature
entry. Its preimage and payload are still checked byte for byte; only the final
signed entry is not compared, and the skip names that reason.

A case the native build refused is not skipped: the harness requires the wasm
build to refuse it too, so a decode that starts succeeding in wasm under its
integer and memory model fails the run. This is where the int64 nonce boundaries
are checked, since the nonce is the value most likely to cross that boundary
differently. A source-account case has no preimage and is skipped, named and
counted, like every other suite.

The harness prints the case counts and the elapsed time. Its budget is 60
seconds; the run takes well under a second on the CI runner, so the budget only
catches a module that hangs rather than a slow-but-correct build.

To freeze a wasm divergence, copy the failing case into
`testdata/wasm-parity/regressions/` (the same schema as a differential case,
with the native bytes recorded) and commit it. The harness replays that
directory on every run.

## What none of them rule out

- **A bug every offline implementation shares.** Each new implementation narrows
  the window — the Rust harness shares the host's own decoder, the differential
  corpus reaches entries nobody wrote down — but all of them are still readers
  of the same CAPs. If every reader misreads the same sentence, every suite
  stays green. Only the host's verdict closes that gap, and only for the entries
  actually submitted.
- **Anything the ledger knows and offline code cannot.** Whether a signing key
  is currently a signer of the account, whether weights meet the threshold,
  whether a nonce was already consumed, whether the expiration is still valid
  (or past `max_live_until_ledger`) at submission time, and whether the fee
  covers the resources — none of these are in the bytes being compared. The same
  boundary, stated per-verdict, is in
  [verification-limits](verification-limits.md).
- **Custom-account acceptance.** The parity suites compare classic ed25519
  payload bytes. A smart wallet's signature is whatever its `__check_auth`
  accepts; only the contract, running on a host, can say whether a given value
  is valid. The passkey shape vectors pin a wallet library's output; the live
  proof that a host accepts that shape is e2e scenarios J and K.
- **The future.** The e2e results record what a host accepted on a date, on
  testnet, at one protocol version. A protocol upgrade, a changed network
  setting, or mainnet state can all invalidate what was true then. The scheduled
  e2e runs exist for exactly this reason.
- **Being audited.** No third party has reviewed this code. Four implementations
  agreeing, plus a host accepting the output, is the best evidence this
  repository can produce — and it is still not a review. Judge accordingly
  before signing anything valuable, and read the code.
