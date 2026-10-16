# Continuous fuzzing

The fuzz targets below are unit tests with a seed corpus — `go test ./...` runs
every seed — and long-running searches on top. CI can only spare seconds per
target, which exercises the seeds but rarely finds anything new. The
`continuous-fuzz` workflow (`.github/workflows/fuzz.yml`) runs the same targets
for much longer: nightly, on every push to `main`, and on demand. That split is
deliberate: a pull request stays fast, and the deep search happens where its
time budget does not block a review.

## The targets

| Target                         | Package            | Property it asserts                                                                                                                                                           |
| ------------------------------ | ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `FuzzValidateDelegateOrder`    | root               | Never panics; every accepted entry has each delegates level strictly ascending by address XDR, with no duplicates.                                                            |
| `FuzzInspect`                  | root               | Never panics; an error always comes with a zero `EntryInfo`, never a half-populated report.                                                                                   |
| `FuzzPreimage`                 | root               | Never panics; anything that decodes either yields a preimage that hashes to a payload, or a clean error.                                                                      |
| `FuzzPayload`                  | root               | Never panics; hashing the same preimage twice agrees.                                                                                                                         |
| `FuzzDecodeAuthorizationEntry` | root               | Never panics; whatever the bounded decoder consumed re-encodes identically without growing; oversize input is refused.                                                        |
| `FuzzVerifyEntry`              | root               | Never reports `verified` for a signature `crypto/ed25519` rejects; a contract node is always `cannot_check`; malformed signatures produce a verdict, never a panic.           |
| `FuzzDiffEntries`              | root               | Diffing an entry against itself is `Identical` with no changes; `PayloadChanged` agrees with `Preimage`/`Payload`; `StaleSignatures` is empty when `PayloadChanged` is false. |
| `FuzzCopyRoundTrip`            | `internal/xdrcopy` | A copy is byte-identical to its source and shares no memory with it.                                                                                                          |

`FuzzDiffEntries` is the one target taking two entries per seed. The wasm parity
harness decodes and hashes one entry at a time and has no `DiffEntries` surface,
so its seeds are recorded in `fuzz_expectations.json` as a
`non_replayed_targets` entry and counted as skipped by `wasm/parity.mjs`, with
the reason printed, rather than replayed.

`FuzzDecodeAuthorizationEntry` documents one decoder behavior worth knowing: the
XDR decoder reads a prefix of its input and ignores trailing bytes, so the
round-trip property holds for the consumed prefix, not for the whole input. A
65-byte input whose first 64 bytes decode is accepted, and re-encodes to
those 64. That is standard decoder behavior, not a finding — and there is a
committed seed proving it stays that way (`trailing_garbage_byte_0`).

## The seed corpus

Seeds come from the golden vectors: `go run ./cmd/gencorpus` decodes every
committed vector and writes it in Go's corpus format under
`testdata/fuzz/<TargetName>`, plus a manifest of what it generated under
`testdata/fuzz/.gencorpus/<TargetName>`. Regeneration deletes exactly the
manifested files before rewriting, so a stale seed disappears while a committed
crash reproducer sharing the directory survives. CI regenerates and fails on
drift, the same way it does for the vectors themselves.

Never hand-edit a generated seed: change the vectors or the generator and
regenerate. Crash reproducers are the exception — they are evidence of a
finding, committed as the fuzzer wrote them (see below).

## What the nightly run does

- One matrix job per target, 15 minutes each (`workflow_dispatch` accepts a
  `fuzztime` override for a deeper run at a keyboard).
- The fuzzer's interesting-inputs cache (`GOCACHE/fuzz`) is restored from the
  previous run and saved again afterwards, even on failure, so each night
  mutates from where the last one left off instead of rediscovering the seeds.
- On a finding the job files an issue titled
  `[fuzz] <Target> found a failing input`, or comments on the one already open
  for that target. The report carries the tail of the fuzz log, the one-command
  local reproduction, and every reproducer the run wrote, base64-encoded and
  ready to land.
- Nothing is auto-committed. The fix and its seed land through an ordinary pull
  request, like any other change.

## Reproduce a finding locally

```sh
# The smoke: every target, 30 seconds each
make fuzz

# One target, deeper (the nightly budget is 15m)
go test -run '^$' -fuzz FuzzInspect -fuzztime 5m .

# A single corpus file, as a regression check with no fuzzing at all
go test -run 'FuzzDecodeAuthorizationEntry/trailing_garbage_byte_0' .
```

`make fuzz FUZZTIME=2m` overrides the per-target budget. The `fuzz` job in
`.github/workflows/ci-go.yml` runs the same 30-second smoke on push to `main`.

## From crash to regression seed

1. Take the reproducer from the issue: decode the base64 block into
   `testdata/fuzz/<Target>/`, keeping the filename the fuzzer wrote.
2. Confirm it fails: `go test -run 'Fuzz<Target>/<filename>' <package>`.
3. Fix the code. If the input turns out to be legal and the target's property
   overstated — as happened with the trailing-byte input above — fix the
   property and say so in the commit body.
4. Confirm the seed passes and the full suite is green: `go test ./...`.
5. Commit the fix and the seed together. The seed now runs on every `go test`,
   which is what makes it a regression test rather than a log line.

The differential harness in `testdata/differential/` is a different kind of
fuzzing — random entries checked across the Go, JS and Python implementations —
and is documented in its own README.
