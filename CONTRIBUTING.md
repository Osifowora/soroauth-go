# Contributing

Thanks for looking. This library produces signatures that move money, so the bar
for changes is higher than the size of the codebase suggests. Most of what
follows exists to keep the evidence honest rather than to police style.

## Your first contribution, in ten steps

The rest of this document is long because it carries the reasoning behind each
rule. This checklist is the short path to a green pull request; each step links
the section that explains it.

- [ ] **1. Pick an issue and get assigned.** Comment on it and wait. Complexity
      and area labels are what work is chosen from — see
      [Picking up an issue](#picking-up-an-issue).
- [ ] **2. Clone and run the suite before changing anything**, so you know a
      later failure is yours: `git clone … && cd soroauth-go && go test ./...`.
      Go 1.25.0 or later is the only requirement for the library and CLI — see
      [Setup](#setup).
- [ ] **3. Branch.** Name it after the work, not the issue number alone:
      `docs/161-onboarding-checklist`, `feat/entry-diff`.
- [ ] **4. Write the test first where you can.** A test that cannot fail reads
      as evidence and is worse than none; if you expect a failure, assert
      _which_ failure — see [What a change needs](#what-a-change-needs).
- [ ] **5. Cite anything you claim about the protocol.** A doc comment, README
      line or commit body that states host behaviour needs the CAP, the
      `rs-soroban-env` file and function, or the SDK file and line. Not memory.
- [ ] **6. Never hand-edit a golden vector.** If your change moves the bytes,
      regenerate with `make vectors` and say in the commit body which CAP
      requires the move — see [Golden vectors](#golden-vectors).
- [ ] **7. Run `make`** — that is `fmt`, `vet` and `test`. If you touched any
      Markdown, also run `npx prettier --write '**/*.md'`, because the build
      checks it. `golangci-lint run ./...` is a local gate worth running too —
      see [Before you open a pull request](#before-you-open-a-pull-request) and
      [Linting](#linting).
- [ ] **8. Commit in conventional form**, lowercase and imperative, one logical
      unit per commit, with the command you ran and its real output in the body
      — see [Commit format](#commit-format).
- [ ] **9. Open the pull request** with one `Closes #<n>` line per issue it
      resolves, what you changed, and how you verified it. A space-separated
      list (`Closes #1 #2`) links only the first issue, and a closing line added
      after the pull request is merged closes nothing, so write them before the
      merge — otherwise an issue the work delivered stays open. Two checks gate
      the merge: `vet and test` and `golden vectors are reproducible`.
- [ ] **10. If the work turned out larger than its complexity label**, say so on
      the issue rather than absorbing it silently.

One thing that is not on the list: do not report a signature-correctness or
key-handling bug in a public issue or pull request. See [Security](#security).

## Picking up an issue

Issues carry a complexity label and an area label, and those two are how work is
chosen; complexity is also what an issue's Stellar Wave points are counted from.
What each label means, who applies it, and who has the final say on complexity
is documented in [docs/labels.md](docs/labels.md).

## Setup

```sh
git clone https://github.com/soroauth/soroauth-go
cd soroauth-go
go test ./...
```

That is the whole setup for the library and CLI. Go 1.25.0 or later.

The pinned `github.com/stellar/go-stellar-sdk` version and the policy for moving
it live in [docs/sdk-support.md](docs/sdk-support.md).

Two optional pieces need more:

- **Regenerating golden vectors** needs Node (>= 22.12.0, what
  `@stellar/stellar-sdk@17.1.0` declares).
- **Running the e2e tests** needs Rust 1.93.0 (pinned in
  `e2e/contracts/rust-toolchain.toml`, rustup will fetch it) and `stellar-cli`
  28.0.0. See [the fixture contract quickstart](docs/fixture-quickstart.md) for
  a step-by-step build and deploy guide from a clean checkout.
- **Working on the wallet SDK adapter** (`adapters/walletsdk`) needs nothing
  extra, but it is a module of its own with its own test loop; see
  [The nested adapter module](#the-nested-adapter-module).
- **Running the Python parity harness** needs Python 3.10+ and the pinned SDK in
  `testdata/parity-python/requirements.txt`; `make parity` creates a venv and
  installs it. The differential fuzzing harness reuses the same venv and SDK:
  `make differential`.
- **Working on the WebAssembly core or the TypeScript wrapper** needs Node (the
  same 22+ the rest of the tooling uses). `make wasm-check` builds the module
  and proves it byte-identical to the golden vectors; `make ts-test` typechecks
  and tests the wrapper package.

## Make targets

The Makefile wraps the common tasks, so the commands below exist in one place
rather than across several documents. Run `make help` for the list.

| Target               | What it runs                                                                                          |
| -------------------- | ----------------------------------------------------------------------------------------------------- |
| `make` (default)     | `fmt`, `vet` and `test`                                                                               |
| `make fmt`           | fails if `gofmt -l .` reports anything                                                                |
| `make vet`           | `go vet ./...`                                                                                        |
| `make test`          | `go test ./...`                                                                                       |
| `make coverage`      | measures test coverage and enforces the per-package floors in `testdata/coverage/floors.json`         |
| `make soak`          | runs the long-running batch signing soak (race detector on, `SOAKTIME`, default 2m)                   |
| `make build`         | builds the CLI to `bin/soroauth`                                                                      |
| `make vectors`       | `cd testdata/gen && npm ci && node gen.mjs && node gen-passkey.mjs`                                   |
| `make vectors-check` | regenerates the vectors and fails if the committed files changed                                      |
| `make demo-check`    | checks the browser demo's logic against the pinned SDK (`node examples/browser-passkey/app.test.mjs`) |
| `make e2e`           | builds the test contract with `stellar-cli` and runs `go test -tags e2e -v ./e2e/...`                 |
| `make parity`        | installs the pinned Python SDK into `.venv-parity` and runs the parity harness and its tests          |
| `make parity-rust`   | runs the Rust stellar-xdr parity harness and its tests (needs Rust 1.93.0)                            |
| `make differential`  | regenerates the differential fuzzing corpus and checks it with the Go, JS and Python implementations  |
| `make wasm`          | builds the js/wasm signing core to `wasm/dist/`                                                       |
| `make wasm-check`    | builds the wasm core and replays every golden vector through it                                       |
| `make ts-test`       | typechecks and tests the `@soroauth/wasm` TypeScript package                                          |
| `make clean`         | removes `bin/`, the wasm build output and the parity venv                                             |

No target hides a failure. `make fmt` exits non-zero when a file needs
formatting instead of printing a warning, `make vectors-check` exits non-zero
when regeneration changes a committed vector, and `make e2e` refuses to run
without `stellar-cli` rather than failing later with an obscure test error.

## Before you open a pull request

```sh
make            # fmt, vet and test
```

The underlying commands are:

```sh
gofmt -l .        # must print nothing
go vet ./...
golangci-lint run ./...
go test -race ./...
```

If your change touches any Markdown, format it too. The `vet and test` job runs
`npx prettier --check '**/*.md'`, so an unformatted file fails the build:

```sh
npm ci                              # once, for the pinned formatter
npx prettier --write '**/*.md'
```

This catches people out, because a branch written before that check existed
fails on files it never touched. Running the line above fixes it. `CLAUDE.md`,
the generated `e2e/RESULTS.md` and the committed vectors are excluded in
`.prettierignore` and should stay that way.

CI runs all of these except `golangci-lint`, plus the golden-vector drift check
and the contract build; the signing-path budget check runs on push to main (see
[Benchmarks](#benchmarks)). `golangci-lint` is a local gate only, because pull
requests are capped at three checks — see [Linting](#linting).

The suite runs with `-race` because `internal/xdrcopy` shares encoder and
decoder buffers across calls through `sync.Pool`; without the detector,
`TestCopyConcurrentReuse` would still pass on code that races.

`internal/xdrcopy` also has a round-trip fuzz target, which the same `-race`
reasoning covers: it asserts a copy is byte-identical to its source and shares
no memory with it. Run it locally with

```sh
go test -fuzz=FuzzCopyRoundTrip -fuzztime=30s ./internal/xdrcopy
```

## Linting

The gate is `.golangci.yml`, run locally. There is no `lint` job in
`.github/workflows/ci.yml`: pull requests are capped at three checks, and the
two that gate a merge are `vet and test` and `golden vectors are reproducible`.
Run the linter before you push; a reviewer may also run it.

The config is deliberately small, and each linter in it is there because the
project would actually fix what it reports; the file says which and why, and
which linters are off on purpose. A linter whose findings are all suppressed
should be deleted rather than left as decoration.

The config was verified against `v2.14.0`. Install that version and run it from
the repository root:

```sh
GOBIN="$PWD/.tools" go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.14.0
./.tools/golangci-lint run ./...
```

`.tools/` is gitignored. `golangci-lint run` prints `0 issues.` and exits 0 when
clean; a finding names the file, the line and the linter. Fix a finding rather
than excluding it. The one documented exception is `fmt.Fprint*` to the CLI's
own stdout/stderr streams, listed under `errcheck.exclude-functions`; adding to
that list needs a reason in the config, not a `//nolint` at the call site.

### The nested adapter module

`adapters/walletsdk` is a Go module of its own, so `./...` from the repository
root does not reach it: the go tool stops at the first directory holding a
`go.mod`. It has its own CI job, and its own loop:

```sh
cd adapters/walletsdk
gofmt -l .
go vet ./...
go test -race ./...
```

It is a separate module on purpose: it is the only place a wallet SDK is named,
and keeping it out of the root module is what stops `go get` of soroauth from
pulling one in. Nothing in the root module may depend on it, and
`TestRootModuleStaysFreeOfWalletSDKs` in the adapter's own tests fails if a
wallet SDK appears in the root `go.mod` or `go.sum`.

Because the two are separate modules, `adapters/walletsdk/go.mod` carries a
`replace` back to the repository root, so the adapter is tested against the
soroauth in this checkout rather than a published version. The root module is
not tagged yet; once it is, the adapter is the module that needs its own
`adapters/walletsdk/vX.Y.Z` tags before anyone outside this repository can
`go get` it.

## Parity harnesses

The golden vectors prove soroauth agrees with `@stellar/stellar-sdk`. They
cannot prove that agreement is _correct_, because a bug shared by both
implementations would be frozen into the vectors. Three harnesses close that gap
by recomputing the vectors with other implementations:

- **Python** (`testdata/parity-python/`), against the separately maintained
  `stellar-sdk` on PyPI. `make parity` imports every vector, rebuilds the
  preimage and payload, and compares. Cases with no preimage (source-account
  entries) are skipped loudly and counted; a run that checks nothing fails.
- **Rust** (`testdata/parity-rust/`), against the separately maintained
  [`stellar-xdr`](https://crates.io/crates/stellar-xdr) crate, which is what the
  Soroban host itself decodes with. `make parity-rust` recomputes every vector's
  preimage and payload and compares; the crate is pinned exactly in `Cargo.toml`
  and `Cargo.lock` and the harness refuses to run against another version. Cases
  with no preimage (source-account entries) are skipped loudly and counted, and
  a run that checks nothing fails.
- **Differential fuzzing** (`testdata/differential/`), which is the one that
  reaches the entries nobody wrote down. `cmd/difffuzz` generates a random but
  deterministic corpus across every credentials arm and records this library's
  preimage and payload for each; `make differential` then requires
  `@stellar/stellar-sdk` and the Python `stellar-sdk` to reproduce every one. A
  case that diverged is frozen into `testdata/differential/regressions/` and
  keeps being checked. **A divergence is a release blocker.**
- **WebAssembly** (`wasm/parity.mjs`), against the wasm build of this same
  library. `make wasm-check` proves the browser build emits the same bytes as
  the native one, replaying the golden vectors, the differential corpus and its
  frozen regressions, and the fuzz seed corpus against the native results
  recorded in `testdata/wasm-parity/fuzz_expectations.json`. A seed the native
  build refused must be refused by the wasm build too.

The golden-vector harnesses are pinned: the Python SDK in `requirements.txt`,
the JS SDK in `testdata/gen/package.json`, the differential verifier's JS SDK in
`testdata/differential/package.json`. **Never edit a vector or a corpus case to
make a harness pass.** A disagreement means one implementation is wrong; open an
issue with the protocol reference (CAP-46-11, CAP-71-01, CAP-71-02) and
investigate.

## The WebAssembly core and the TypeScript wrapper

`cmd/soroauthwasm` compiles the signing core to `js/wasm`. It is a thin binding
over the same `soroauth` package the native build uses — it does not reimplement
anything — and it is behind `//go:build js && wasm`, so `go build ./...` visits
it only when you ask for that target. `wasm/build.sh` builds it together with
the matching `wasm_exec.js`.

`wasm/ts` is the `@soroauth/wasm` npm package: a typed wrapper over those
bindings. It is a wrapper, not a second implementation, and its tests run under
jsdom plus a real-wasm integration test.

The interactive TUI (`tui.go`) is excluded from js/wasm builds, because
bubbletea does not compile for that target. The CLI, which is never built for
js/wasm, still has it.

## Benchmarks

The signing path has committed benchmarks in `bench_signing_test.go` covering
`Preimage`, `Payload`, `AuthorizeEntry` on all three arms (legacy, V2,
delegates, including a depth-8 delegate chain), `AuthorizeAll` over a 12-entry,
4-signer batch, and `BenchmarkXDRCopy` — the deep copy in `internal/xdrcopy`
that every entry-returning function performs, in its two on-path shapes (an
authorization entry and a `HashIdPreimage`).

Issue #365 split the gate into a **separate budget per operation and per
credential arm**, so a regression in one arm cannot hide behind an improvement
in another. `bench_arms_test.go` adds `BenchmarkVerifyEntry` and
`BenchmarkDiffEntries` on each of the three arms, plus `BenchmarkDelegateTree`,
which signs a delegate chain parameterised by node count (`nodes_1`, `nodes_4`,
`nodes_16`, `nodes_63`) so super-linear growth in the recursive walk is visible.
Each budget in `testdata/bench/budgets.json` may name the operation and arm it
gates; `checkbench` prints that label on failure (`verification/delegates`)
instead of an opaque Go benchmark path, and always prints the underlying
benchmark name too.

```sh
# Full suite with allocation stats
go test -run '^$' -bench . -benchmem -count=1 .

# One arm
go test -run '^$' -bench 'BenchmarkAuthorizeEntry/delegates' -benchmem .
```

CI runs the same command and gates on **allocs/op and B/op** only, via:

```sh
go test -run '^$' -bench . -benchmem -count=1 . | tee /tmp/bench.out
go run ./scripts/checkbench /tmp/bench.out testdata/bench/budgets.json
```

`ns/op` is reported for humans in PRs (with the machine it came from) but never
fails the build: wall-clock on a shared runner is noise. Allocation counts are
deterministic for a given Go version and are the regression signal.

`testdata/bench/budgets.json` is the committed baseline. Signing-path budgets
carry ~40% headroom over the measured values so a Go minor bump does not flake
CI. If the checker fails:

- If the increase is a bug, fix the bug; do not raise the budget.
- If the increase is intentional, raise the budget in the **same commit** as the
  change and say in the commit body which function got more expensive and why
  that is acceptable.
- Never lower a budget without a fresh local measurement on the machine named in
  the commit body.

When you add a benchmark, add a budget in the same commit. The checker prints
`WARN … no budget` for any benchmark it sees without one, and
`FAIL … benchmark not found` if a budgeted name is missing from the output — so
a renamed benchmark cannot silently drop out of the gate.

### Reproducing a budget failure locally

A CI failure from the `bench` job is a `FAIL` line naming the operation and arm,
the measured value, and the committed baseline, with the benchmark path on the
following line:

```
FAIL verification/delegates        allocs/op 49 > baseline 10
                                   benchmark BenchmarkVerifyEntry/delegates  (143581 ns/op)
```

The two commands above, run from the repository root, reproduce it locally —
`checkbench` exits 1 exactly as CI does. Once you can see _which_ operation and
arm regressed, find out _where_ the allocations come from:

```sh
go test -run '^$' -bench BenchmarkXDRCopy -benchmem -count=1 -memprofile /tmp/mem.out .
go tool pprof -alloc_objects -top /tmp/mem.out   # rank by number of allocations
go tool pprof -alloc_space  -top /tmp/mem.out    # rank by bytes
```

The signing-path entries (`AuthorizeEntry`, `AuthorizeAll`) also include ed25519
signing and SHA-256; `BenchmarkXDRCopy` isolates the deep copy, so a regression
that moves both almost always starts in `internal/xdrcopy`.

The `BenchmarkXDRCopy` budgets are deliberately tighter than the ~40% policy:
they sit **below** what a copy cost before the round-trip buffers were pooled
(issue #108), so reverting that pooling fails this gate instead of only a local
run. If they fail after a change that never touched `internal/xdrcopy`, profile
with the commands above before moving the number, and if the new cost is
justified, raise it in the same commit with the measurement in the body.

## Verifying README snippets compile

The README's Go examples (Quickstart, Delegates, and the inline `AllowResign`
snippet) are not free-standing markdown text: each is extracted verbatim from a
real, compiling source file in `internal/readmesnippets/`, between a
`// snippet:start <name>` and `// snippet:end <name>` comment pair.
`TestReadmeSnippetsMatchTheirSource` in `readme_test.go` at the repository root
asserts the fenced code block in README.md is byte-identical (modulo
tabs-vs-spaces) to that marked region. The guides under `docs/` — `passkeys.md`,
`migrating.md` — are checked the same way by
`TestGuideSnippetsMatchTheirSource`.

This means two different things can fail, and the test names which:

- **The snippet source stops compiling.** It is an ordinary package with no
  build tag, so `go build ./...` and `go vet ./...` — which CI already runs on
  every push — catch this like any other compile error, naming the file and
  line.
- **The README drifts from its source**, for example a hand-edit to the fenced
  block without updating `internal/readmesnippets/`, or the reverse.
  `TestReadmeSnippetsMatchTheirSource` fails and prints both texts.

To reproduce either failure locally:

```sh
go build ./...                        # catches a snippet that no longer compiles
go test -run TestReadmeSnippets -v .  # catches README/source drift, naming the snippet
```

To change an example, edit the marked region in `internal/readmesnippets/*.go`
and copy it verbatim (as, or converted from, tabs) into the matching fenced
block in README.md. Never edit the fenced block alone: it is not the source of
truth, and the drift test will fail on the next run.

## Protocol version matrix

`ArmProtocolVersion` (`protocolmatrix.go`) and the README's "Protocol version
support" table both claim the same thing — which Stellar protocol version each
credential arm requires — sourced from each arm's CAP preamble (CAP-46-11 for
the source-account and legacy arms, CAP-71-01 and CAP-71-02 for V2 and the
delegates arm). `TestArmProtocolVersionMatchesTheReadme` in
`protocolmatrix_test.go` parses the README table and fails if its numbers
disagree with `ArmProtocolVersion`, and `TestArmProtocolVersionMatchesTheCAPs`
pins `ArmProtocolVersion` itself to the values read directly from the CAPs.

To reproduce a failure locally:

```sh
go test -run TestArmProtocolVersion -v .
```

Changing a protocol version claim means updating both `protocolmatrix.go` and
the README table together, in the same commit, and citing the CAP text that
justifies the change — never editing one side to make the test pass.

## GitHub Actions are pinned to commit SHAs

Every `uses:` in `.github/workflows/*.yml` names a full commit SHA with the
version in a trailing comment, e.g. `actions/checkout@3d3c42e… # v7`, never a
mutable tag like `@v7`. A major-version tag can be retagged to point at a
different commit; pinning to the SHA means a compromised or retagged action
cannot silently start running with this repository's CI permissions.

Dependabot (`.github/dependabot.yml`) watches the `github-actions` ecosystem and
opens a PR updating both the SHA and its version comment together when a new
release comes out, so the two can never drift apart. To pin a new action by
hand, resolve the tag to a commit first:

```sh
git ls-remote --tags https://github.com/<owner>/<repo> | grep 'refs/tags/v7$'
```

Use the first column's SHA (for an _annotated_ tag, `git ls-remote` also prints
a `refs/tags/v7^{}` line — use that dereferenced commit SHA, not the tag
object's own SHA).

## Editing a workflow

Two things about `.github/workflows/*.yml` that are easy to get wrong, because
neither produces an error.

**A `paths:` filter produces no check at all**, not a skipped one. A workflow
that does not match is simply absent from the pull request, so a failure in it
is invisible during review and is inherited by `main` on merge. That is how
`spellcheck` stayed red across three merges: #286 added a word to this file, the
workflow is `paths:`-filtered, and there was no row to look at. An `if:`-gated
_job_ still reports a row; a `paths:`-filtered _workflow_ does not.

So when you check whether a branch is green, list runs per workflow rather than
reading the pull request's checks:

```sh
for f in .github/workflows/*.yml; do
  gh run list --branch main --workflow "$(basename "$f")" --limit 1 \
    --json conclusion,headSha,displayTitle
done
```

**Every advisory workflow lists its own file in its `paths:`**, so an edit to a
workflow re-runs it. Without that line a change to a workflow cannot validate
itself: #294 changed only `ci-adapters.yml`, matched nothing in that workflow's
own filter, and landed on `main` with its new job never having run once. If you
add a workflow with a `paths:` filter, include its own path.

### Release attestations and signatures

Every release artifact is attested and signed, and the way to check that is a
script rather than prose, so it can run in CI:

- `scripts/verify-release.sh` verifies a downloaded release: every binary
  against its `.sigstore.json` bundle (cosign, keyless) and its build provenance
  attestation (`gh attestation verify`), every attached `.spdx.json` SBOM
  against its SBOM attestation, and the container image digest the release
  names. `--tamper-demo` flips one byte in a verified binary and requires
  **both** paths to reject the copy, because a check nobody has seen reject
  something is not evidence.
- The `verify-release` job in `.github/workflows/release.yml` runs the script
  against the release it just published, so a release whose assets do not verify
  stays red instead of being announced.
- `.github/workflows/verify-release.yml` re-runs it weekly against the newest
  release that carries bundles (releases from before the scheme are skipped with
  a message, not failed). Its `self_test` dispatch input builds a throwaway
  binary from any ref and runs the same script plus the tamper demo on the run's
  own OIDC identity — that is the evidence to attach to a pull request that
  touches this scheme:

  ```sh
  gh workflow run verify-release.yml --repo <owner>/soroauth-go \
    --ref <branch> -f self_test=true
  ```

Signing is keyless: the certificate comes from the workflow's GitHub OIDC
identity, so no key exists in CI to leak or rotate. The flip side is that an
action added to a job that can mint an OIDC token in these workflows runs with
that identity and writes attestations under it, which is one more reason every
new action must be SHA-pinned as described above — and why the verification
commands in the README and in `scripts/verify-release.sh` pin the _identity_
(this repository's workflow at a tag), not a key.

## Golden vectors

`testdata/vectors/*.json` are generated, committed artefacts. They are the
evidence that soroauth agrees byte-for-byte with the reference implementation.

**Never edit a vector by hand.** Not to fix a failing test, not to adjust a
field, not for anything. A hand-edited vector is a test that has been made to
agree with the code instead of the other way round, which is precisely the
failure the vectors exist to prevent. CI regenerates them on every push and
fails if the committed files differ, so an edit will be caught — but the reason
not to do it is that it destroys the evidence, not that you will be caught.

There are two generators, because there are two things being proven:

- `gen.mjs` writes `testdata/vectors/*.json`, the authorization-entry vectors,
  against a pinned `@stellar/stellar-sdk`.
- `gen-passkey.mjs` writes `testdata/vectors/passkey/*.json`, the passkey
  signature-shape vectors, against a pinned `smart-account-kit`. The passkey
  shape is not protocol-defined — a custom account's `__check_auth` decides it —
  so there is no CAP to cite and the evidence is a real wallet library's output
  instead.

To change them, change the generator:

```sh
cd testdata/gen
npm ci
node gen.mjs
node gen-passkey.mjs
```

Then commit the regenerated files together with the generator change.

### Versioning the vector schema and reproducing failures

Every golden vector carries an explicit `schema_version` field (currently `1`).
The loader (`golden_test.go`) explicitly checks this version and rejects any
unknown or missing schema version rather than guessing or ignoring
removed/reinterpreted fields.

- **Bumping the version:** When a protocol change or schema evolution requires
  altering the structure of golden vectors, increment `schema_version` in both
  the generator (`testdata/gen/gen.mjs`) and all committed vector JSON files
  under `testdata/vectors/`, and update the expected version check in
  `golden_test.go`.
- **Reproducing a failure locally:** If a vector fails schema validation or
  drifts from the reference implementation, run `go test -run TestGoldenVectors`
  (or `make vectors-check`) from the repository root. The test suite will fail
  loudly, naming the vector and the exact mismatch or unsupported schema
  version.

If a vector disagrees with the Go code, the Go code is wrong until proven
otherwise. If you believe the vector itself is wrong, stop and open an issue
saying why, with the protocol reference — do not change it to make a test pass.

Each generator refuses to run against a library other than the version it is
pinned to, since a vector from another build is not evidence about this one.
`gen-passkey.mjs` additionally records the `@stellar/stellar-sdk` version
`smart-account-kit` resolved and refuses a mismatch, and
`passkey_golden_test.go` asserts both the inner signature map and the library's
complete output, so the one-element vector `smart-account-kit` wraps its map in
is pinned rather than assumed.

### Frozen release entries

The golden vectors move with the code: `make vectors` regenerates them in the
same commit as any change. That is what they are for, and it is also why they
cannot catch a wire-format regression in reading a stored, pre-signed entry —
the vector and the reader change together.

`testdata/frozen/<release>/` is the opposite: entries signed by an earlier
release, committed once and **never regenerated**. `frozen_test.go` asserts the
current code still decodes each to the same bytes, rebuilds the payload the
release recorded, verifies the signature and inspects to the same structure. If
one ever stops verifying, that is a wire-format regression and must stop the
build, not be re-recorded.

The set is kept out of `testdata/vectors/`, and `make vectors-check` (and CI)
diffs it as well, so a generator that wrote there would fail the check. To add a
set for a new release, follow
[`testdata/frozen/README.md`](testdata/frozen/README.md) — check out the tag,
run `scripts/frozengen` inside that worktree, and commit the output.

## Deterministic test keys

Every key in the tests, examples, benchmarks and golden vectors is derived from
a plaintext label committed in this repository. Signatures are then
reproducible: ed25519 is deterministic, so the same label, payload and code give
the same bytes on every machine and in every implementation. That is what lets a
golden vector assert byte equality.

The derivation is SHA-256 of the label, used as the seed:

| Key                     | Go                                                                           | JS (`testdata/gen/`)                                             |
| ----------------------- | ---------------------------------------------------------------------------- | ---------------------------------------------------------------- |
| ed25519 account (`G…`)  | `keypair.FromRawSeed(sha256.Sum256([]byte(label)))`                          | `Keypair.fromRawEd25519Seed(sha256(label))`                      |
| contract address (`C…`) | `strkey.Encode(strkey.VersionByteContract, sha256(label))`                   | `Address.contract(sha256(label))`                                |
| P-256 passkey key       | private scalar `sha256(label) mod n` (`testPasskeyKey` in `passkey_test.go`) | `sha256(label)` as the private key or scalar (`gen-passkey.mjs`) |

For example, the golden vectors sign with the label `soroauth-vector-signer-1`,
and `ExampleAuthorizeEntry` uses `soroauth-example-account`. A few examples
(`constructor_examples_test.go`, `signer_test.go`) pass a literal seed such as
`[32]byte{1, 2, 3}` instead. Those keys are just as public.

**These keys are public.** Anyone who reads the label can derive the secret key
and spend from the account. They exist only to make tests reproducible. Never
fund them on mainnet, and never send them anything of value on any network.

When you add a test:

- Derive keys with the helper your package already has, such as `testKeypair` in
  `address_test.go`, and pass a new label that says what the key is for
  (`soroauth-<area>-<role>`). Do not invent key bytes by hand.
- Do not rename a `soroauth-vector-signer-*` label. `gen.mjs` derives the
  vectors' keys from those labels, so renaming one breaks every vector signed
  with it.
- Never use this scheme for a key that holds value. The e2e tests need funded
  accounts, so they call `keypair.Random()` (`e2e/harness_test.go`), fund the
  accounts from friendbot on testnet, and never write the keys to disk.

## Shared fixture deployment harness & running e2e tests

The e2e test suite provides a shared fixture deployment harness
(`deployAndFundFixture` on the test `harness`) so individual contract fixtures
do not reimplement deployment and funding logic.

To deploy and fund any contract fixture in your own scenarios or local
debugging:

```go
deployer := h.newAccount(t, "deployer")
wasmBytes := wasmPath("modular_account")
contractID := h.deployAndFundFixture(t, deployer, wasmBytes, constructorArgs...)
```

## Running the e2e tests

```sh
cd e2e/contracts && stellar contract build
cd ../.. && go test -tags e2e -v ./e2e/...
```

They run against testnet by default; `SOROAUTH_RPC_URL` points them elsewhere.
Accounts are generated at runtime and funded by friendbot. A full run takes
about three minutes.

`e2e/RESULTS.md` is written by a run and only when every scenario ran. Commit it
only from a real, complete run — it is what the README's testnet claims point
at.

See [e2e/README.md](e2e/README.md) for what each scenario proves and why the two
rejection scenarios exist. For a step-by-step guide to building and deploying
the fixture contracts manually from a clean checkout, see
[the fixture contract quickstart](docs/fixture-quickstart.md).

## Scheduled e2e runs (CI)

A GitHub Actions workflow (`.github/workflows/e2e.yml`) runs the e2e suite on a
schedule (every 6 hours) and on `workflow_dispatch`. This catches testnet
resets, protocol upgrades, and RPC changes that would otherwise break the suite
silently between releases.

- The workflow **does not** commit `e2e/RESULTS.md` automatically — that remains
  a deliberate act from a verified local run.
- On scheduled failure, the workflow opens a GitHub issue with the run details
  so the regression is visible without digging through logs.
- To reproduce a scheduled failure locally:
  ```sh
  export SOROAUTH_RPC_URL=https://soroban-testnet.stellar.org
  go test -tags e2e -v ./e2e/...
  ```

## Parity reports

The e2e suite writes a machine-readable `parity-report.json` alongside
`RESULTS.md`, listing every scenario with its vector id, implementation, verdict
and observed credential arm, so a parity regression can be read by a tool rather
than by eye.

`TestParityReportRegression` checks that report's shape: a non-zero scenario
count, and a vector id and verdict on every entry. It needs no network — when no
live report is present it reads the committed fixture at
`e2e/testdata/parity_regression.json` — so it runs in CI as a step of the
`vet and test` job, and a regression fails the build rather than only a local
run:

```sh
go test -tags e2e -run TestParityReportRegression ./e2e
```

To debug a failure, inspect the generated `parity-report.json` in the repository
root after a full e2e run; it carries the per-scenario verdicts the test is
asserting over.

## Coverage reporting (CI)

The `coverage` job in `.github/workflows/ci-go.yml` measures test coverage,
checks it against the committed per-package floors in
`testdata/coverage/floors.json`, and publishes the report via Codecov. It runs
on push to `main` and on demand, not on pull requests: pull requests carry only
the three checks the branch ruleset requires.

This replaced one repository-wide floor of 60%. A single floor lets a
well-covered package subsidise a thin one: the signing path was averaged
together with the CLI and the examples, so a real regression in the former could
hide behind the latter. Each package now carries its own floor, set from the
measurement recorded next to it — a floor nobody can meet gets raised away —
with a one-line reason each. **The signing path (the root package and
`internal/xdrcopy`) carries floors strictly above the 60% repository-wide floor
this scheme replaced**, so a regression in the path that produces signatures
cannot hide behind a repository average; `scripts/checkcov` enforces that
minimum as policy.

Packages with no tests by design are **excluded by name**, with a reason each,
never given a floor of zero: the examples are documentation exercised by the
golden and e2e runs, and `cmd/gencorpus`, `scripts/checkbench` and
`scripts/frozengen` are development tools CI runs itself. If an excluded package
gains tests, the checker fails until the table says what to do.

`scripts/checkcov` fails naming the package and both numbers when a package
drops below its floor, when a package has neither a floor nor an exclusion, and
when the table and the tree disagree — a floor for a package that has been
renamed away, or one raised above the measurement it was set from. It also
filters `node_modules/` out of the profile: the root `npm ci` installs
`node_modules/flatted/golang`, which a local run would otherwise see and CI
never measures.

Coverage is not correctness: it says which lines ran, not that the result is
right. The mutation-testing work planned over the signing path
([docs/WAVE10_BACKLOG.md](docs/WAVE10_BACKLOG.md), "test: mutation testing over
the signing path") is the stronger check; these floors are a tripwire for
regressions, not evidence of correctness.

Reproduce the job with one command:

```sh
make coverage
```

which is:

```sh
go test -coverprofile=coverage.out -covermode=atomic ./...
go list -f '{{.ImportPath}}' ./... > packages.txt
go run ./scripts/checkcov coverage.out testdata/coverage/floors.json packages.txt
```

`make coverage` derives the toolchain from the `toolchain` line in `go.mod` and
runs each command under it, because statement counts move between Go minor
versions — go1.27 counts the `server` package about 4.5 points lower than
go1.25.4 — and the floors were measured with the pinned toolchain. CI does the
same.

When a floor fails, `go tool cover -func=coverage.out` shows which functions
moved, and the fix is the tests, not the floor. Changing a floor needs a fresh
measurement named in the commit body; never lower one to make CI green.

## Property-based tests

The address package includes property-based tests using
[gopter](https://github.com/leanovate/gopter). These tests generate thousands of
random G... and C... addresses and verify:

- ParseAddress/FormatAddress round-trips for both address types
- XDR encoding stability across round-trips
- Rejection of invalid inputs (muxed addresses, secret seeds, liquidity pools,
  claimable balances, malformed base32, corrupted checksums, truncated
  addresses, empty strings)

### Running property tests locally

```sh
# Run the full property test suite (1000 iterations per property)
go test -run TestParseAddressFormatAddressProperty -v ./...

# Run the deterministic subset (100 iterations, fixed seed for CI reproducibility)
go test -run TestParseAddressFormatAddressDeterministic -v ./...

# Run the complementary XDR-level tests
go test -run 'TestParseAddressWithRandomXDR|TestFormatAddressRejectsInvalidXDR' -v ./...
```

### Reproducing a property test failure

If a property test fails, the output will show the seed and the generated value
that causes the failure. To reproduce:

```sh
# 1. Note the seed from the failure output (e.g., "failed with initial seed: 12345")
# 2. Run with that seed:
go test -run TestParseAddressFormatAddressProperty -v -count=1 ./... 2>&1 | head -50

# Or run the deterministic test which uses a fixed seed:
go test -run TestParseAddressFormatAddressDeterministic -v ./...
```

Similarly, to run and reproduce expiration and signature consistency property
tests for `AuthorizeEntry` across all address arms and delegate tree depths:

```sh
go test -run TestAuthorizeEntryExpirationProperty -v ./...
```

The deterministic test (`TestParseAddressFormatAddressDeterministic`) runs a
fixed set of 100 iterations per property with seed `0xDEADBEEF` and is the one
executed in CI. If it passes locally but the full property test fails, the
failure is in the extended search space — increase `MinSuccessfulTests` in the
deterministic test to narrow it down.

### Fuzzing

The full story lives in [docs/fuzzing.md](docs/fuzzing.md): the eight targets
and the property each asserts, the nightly `continuous-fuzz` workflow that runs
them beyond CI's time budget, and the crash-to-regression-seed process. What
follows is what you need while working.

The short loop:

```sh
make fuzz               # every target, 30s each (override: make fuzz FUZZTIME=2m)
go run ./cmd/gencorpus  # regenerate the seed corpus from the golden vectors
```

#### The eight fuzz targets

| Target                         | Package            | Run command                                                                  |
| ------------------------------ | ------------------ | ---------------------------------------------------------------------------- |
| `FuzzValidateDelegateOrder`    | root (`.`)         | `go test -run '^$' -fuzz FuzzValidateDelegateOrder -fuzztime 30s .`          |
| `FuzzInspect`                  | root (`.`)         | `go test -run '^$' -fuzz FuzzInspect -fuzztime 30s .`                        |
| `FuzzPreimage`                 | root (`.`)         | `go test -run '^$' -fuzz FuzzPreimage -fuzztime 30s .`                       |
| `FuzzPayload`                  | root (`.`)         | `go test -run '^$' -fuzz FuzzPayload -fuzztime 30s .`                        |
| `FuzzDecodeAuthorizationEntry` | root (`.`)         | `go test -run '^$' -fuzz FuzzDecodeAuthorizationEntry -fuzztime 30s .`       |
| `FuzzVerifyEntry`              | root (`.`)         | `go test -run '^$' -fuzz FuzzVerifyEntry -fuzztime 30s .`                    |
| `FuzzDiffEntries`              | root (`.`)         | `go test -run '^$' -fuzz FuzzDiffEntries -fuzztime 30s .`                    |
| `FuzzCopyRoundTrip`            | `internal/xdrcopy` | `go test -run '^$' -fuzz FuzzCopyRoundTrip -fuzztime 30s ./internal/xdrcopy` |

Run all eight with one command:

```sh
make fuzz                       # 30s each
make fuzz FUZZTIME=2m           # 2 minutes each
```

#### Seed corpus location

The seed corpus lives in `testdata/fuzz/<TargetName>/` for the seven
root-package targets, and in `internal/xdrcopy/testdata/fuzz/FuzzCopyRoundTrip/`
for `FuzzCopyRoundTrip`. Go reads a target's seeds **only** from its dedicated
directory; files elsewhere are ignored. Every file must be in Go's corpus format
(a `go test fuzz v1` header followed by one Go literal per fuzz argument). A
file in the wrong format fails the package's tests rather than being skipped.
`FuzzDiffEntries` is the one target whose seeds carry two `[]byte` literals, one
per argument.

Regenerate the seeds from the committed golden vectors:

```sh
go run ./cmd/gencorpus
```

This is deterministic: the same vectors produce byte-identical corpus files. CI
runs it on every push and fails if the committed seeds drift.

#### Running a single seed as a regression test

Each corpus file runs as a named subtest under `go test ./...` with no `-fuzz`
flag. To run one seed by name:

```sh
go test -run 'FuzzValidateDelegateOrder/v2_sub_invocations_0' -v .
```

#### Reproducing a CI crash locally

When the nightly `continuous-fuzz` workflow finds a crash, it files (or comments
on) an issue titled `[fuzz] <Target> found a failing input`. The issue body
includes:

- The tail of the fuzz log.
- The one-command local reproduction (e.g.,
  `go test -run '^$' -fuzz FuzzInspect -fuzztime 30s .`).
- Every reproducer the run wrote, base64-encoded, ready to decode into the
  target's seed corpus directory.

To reproduce:

1. Decode the base64 block into `testdata/fuzz/<Target>/`, keeping the filename
   the fuzzer wrote.
2. Confirm it fails:

   ```sh
   go test -run 'Fuzz<Target>/<filename>' <package>
   ```

   Example:

   ```sh
   go test -run 'FuzzInspect/trailing_garbage_byte_0' .
   ```

3. Fix the code. If the input turns out to be legal and the target's property
   overstated — as happened with the trailing-byte input — fix the property and
   say so in the commit body.
4. Confirm the seed passes and the full suite is green:

   ```sh
   go test ./...
   ```

5. Commit the fix and the seed together. The seed now runs on every `go test`,
   which is what makes it a regression test rather than a log line.

The differential harness in `testdata/differential/` is a different kind of
fuzzing — random entries checked across the Go, JS and Python implementations —
and is documented in its own README.

### Soak testing

`TestSoakBatchSigning` in `soak_test.go` is the long version of the batch
signing test. It lives behind the `soak` build tag, so `go test ./...` never
compiles it, and it signs batches of the committed golden vectors from several
goroutines, round after round, for a caller-chosen duration. After every round
it asserts that every signed entry is byte-identical to the vector's recorded
`signed_entry_xdr`, that the goroutine count is back to the baseline taken after
a warm-up round, and that live heap (`HeapAlloc`, after a `runtime.GC`) is
within the documented headroom of that baseline. The byte equality is what
catches a pooled `internal/xdrcopy` buffer handed to two callers; the memory
assertions catch a leak that only shows up over hours.

```sh
make soak                # 2m local smoke, race detector on
make soak SOAKTIME=10m   # the nightly budget
```

It is **not** a replacement for `go test -race` or for
`TestCopyConcurrentReuse`: those prove correctness under contention for the
duration of a short run, while the soak watches the steady state for minutes and
hours. The `soak` job in `.github/workflows/fuzz.yml` runs the ten-minute
version on the same nightly schedule as the fuzz targets. The reported run, the
machine it came from and the measurements the tolerances were set from are in
[docs/soak.md](docs/soak.md).

### Capturing regressions

If a property test discovers a bug, capture the failing input as a regression
fixture in `address_test.go` by adding a new table entry to
`TestParseAddressRejects` or `TestParseAddressFormatAddressRoundTrip` with the
exact address string that triggered the failure. This ensures the specific case
remains covered even if the property test parameters change.

## Doc comments on exported identifiers

Every exported const, var, type, func, and method on an exported type needs a
doc comment. `internal/doccheck` enforces this: it walks the module's
first-party packages (skipping `adapters/walletsdk`, which is a nested module
checked by its own CI job) and fails on any exported identifier with none.
`TestRoot_RepoIsClean` in `internal/doccheck/doccheck_test.go` runs it as part
of the normal suite, so `go test ./...` fails the same way CI does.

Reproduce a failure locally:

```
go test ./internal/doccheck/... -run TestRoot_RepoIsClean -v
```

Each line names the file, the line, and the identifier. A const or var block can
be documented either per entry or with one comment above the block (both count);
a method only needs a doc comment when its receiver type is itself exported,
since a method on an unexported type is not reachable through godoc.

## What a change needs

- **Tests that can fail.** A test that passes for the wrong reason is worse than
  no test, because it reads as evidence. Two of this repo's own tests were
  originally written that way and had to be fixed: a rejection scenario that
  asserted only "the transaction failed" was passing while the transaction ran
  out of instructions and never reached the check it was supposedly about. If
  you add a test that expects a failure, assert _which_ failure.
- **A test that proves the guard bites.** Where practical, break the thing
  deliberately, confirm the test fails, and say so in the commit message. Do not
  commit the break.
- **No mutation of caller input.** Every function returning a modified entry
  deep-copies first and has a test proving the input's bytes are unchanged.
- **Errors that name the sentinel.** Wrap with
  `fmt.Errorf("soroauth: <operation>: %w", err)` and match with `errors.Is`.
- **Every exported sentinel has a test that produces it.** This is checked, not
  trusted: `TestEverySentinelHasAProducingTest` in `errors_meta_test.go` parses
  the `Err*` names out of `errors.go`, scans every `_test.go` in the package,
  and fails naming any sentinel no test mentions. So adding a sentinel without a
  test fails the build.

  The check is deliberately loose about _how_ a sentinel is asserted — directly
  through `errors.Is`, through a `want` field in a table, through a `sentinel`
  field — because all three are used here and a check that recognised only one
  would fail honest tests. It therefore proves a sentinel is not forgotten, not
  that it is well tested. If a sentinel is no longer produced by any code path,
  delete it rather than writing a test to satisfy the check.

- **Context is checked and passed down, never dropped.** Every exported function
  that takes a `context.Context` as its first parameter must check `ctx.Err()`
  before doing work — so a cancelled context fails closed even on a path that
  never reaches a signer (a source-account entry, an empty batch) — and must
  pass that same context, unchanged, to every call that can block or produce a
  signature, in particular `Signer.Sign`. Every such function has a cancellation
  test that asserts `context.Canceled` and that the signer was not invoked; add
  one for any new context-taking function.
- **Fail closed.** Where the protocol or the caller's intent is ambiguous,
  refuse and return an error rather than guess. Say which reading you chose in
  the commit message.
- **Cited protocol claims.** Any statement about host behaviour in a doc
  comment, README or commit message needs a source — the CAP, the
  `rs-soroban-env` file and function, or the SDK file and line. Not memory.

## Commit format

Conventional commits, lowercase and imperative:

```
feat(authorize): sign delegate nodes by address
test(golden): cover delegate vectors
docs(readme): write readme
ci: add golden drift job
```

One logical unit per commit — a function and its tests, one CLI subcommand, one
document. Commit bodies carry the evidence: the command you ran and its real
output, or the file and line you read.

A commit that corrects an earlier wrong claim or wrong code is its own commit,
and its body says what was wrong, how it was found, and what changed.

## Security

Do not open a public issue for a signature-correctness or key-handling bug. See
[SECURITY.md](SECURITY.md). The security issue template redirects to private
advisories rather than collecting a report — use it rather than a blank issue,
and never paste vulnerability details into any public form.

## License

By contributing you agree your contributions are licensed under Apache-2.0.

### No per-file license headers

Source files deliberately carry no license header. The whole repository is
Apache-2.0, declared once in [LICENSE](LICENSE) at the root, which is what
GitHub and `pkg.go.dev` read to report the license. Apache-2.0 does not require
a header in each file: the boilerplate notice is in its appendix, which follows
"END OF TERMS AND CONDITIONS" in [LICENSE](LICENSE), so it is guidance on
applying the license rather than one of its terms. A header copied into hundreds
of files adds nothing the root file does not already say, and a header that
drifts from `LICENSE` would be worse than none.

So do not add a header to a file you create, and do not add an SPDX line. Files
copied in from another project under a different license are the exception: they
keep their original notice, and the pull request says where they came from.
Because no header is adopted, there is no CI check for one.
