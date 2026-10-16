# Makefile for the tasks CONTRIBUTING.md and ARCHITECTURE.md describe.
#
# Every target fails loudly: no recipe swallows an error, and targets that
# check something (fmt, vectors-check) exit non-zero when the check fails
# rather than printing a warning and moving on.
#
# Run `make` or `make help` for the list.

GO   ?= go
NPM  ?= npm
NODE ?= node

# The toolchain go.mod pins. Coverage statement counts move between Go minor
# versions (go1.27 counts the server package ~4.5 points lower than go1.25.4),
# so `make coverage` runs its measurement under the pinned toolchain to agree
# with the numbers recorded in testdata/coverage/floors.json.
COVER_TOOLCHAIN := $(shell awk '/^toolchain /{print $$2}' go.mod)

# The binary `make build` writes, relative to the repository root.
BIN_DIR := bin
BIN     := $(BIN_DIR)/soroauth

# Build metadata the CLI reports with --version. The release workflow overrides
# all three with the tag, the commit and the run's date (see
# .github/workflows/release.yml); a local `make build` reports the checkout it
# was built from, which is what makes a bug report against a locally built
# binary actionable. Each falls back to a self-describing value rather than an
# empty string, so a source tarball with no git metadata still builds.
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT     ?= $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS    := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(BUILD_DATE)

# How long `make fuzz` runs each target. The continuous workflow
# (.github/workflows/fuzz.yml) runs the same targets for much longer; this is
# the local smoke that proves a target starts and its seeds pass.
FUZZTIME ?= 30s

# How long `make soak` signs batches. The scheduled `soak` job in
# .github/workflows/fuzz.yml runs the same test for ten minutes; this default
# is the local smoke that proves the loop starts and every round's assertions
# hold. The race detector stays on either way: docs/soak.md explains why the
# soak is not a replacement for it.
SOAKTIME ?= 2m

.PHONY: all help fmt vet test coverage fuzz soak build server man md-check md-format vectors vectors-check demo-check diagrams diagrams-check e2e clean parity parity-rust differential wasm wasm-check wasm-budget ts-test jvm-test jvm-native rust-test grpc-test grpc-check freighter-check openapi-test openapi-check action-test

# The default target runs exactly what a pull request has to pass before the
# golden-vector drift check, which needs Node and the network.
all: fmt vet test

help:
	@echo "targets:"
	@echo "  make all           fmt, vet and test (the default)"
	@echo "  make fmt           fail if any Go file is not gofmt-clean"
	@echo "  make vet           go vet ./..."
	@echo "  make test          go test ./..."
	@echo "  make coverage      measure coverage and enforce the per-package floors"
	@echo "  make fuzz          run every fuzz target for \$$(FUZZTIME) each (default 30s)"
	@echo "  make soak          soak the batch signing path for \$$(SOAKTIME) (default 2m, race detector on)"
	@echo "  make md-check      fail if any Markdown file is not prettier-clean"
	@echo "  make md-format     format every Markdown file in place"
	@echo "  make build         build the CLI to $(BIN)"
	@echo "  make server        build the verification service to $(BIN_DIR)/soroauth-server"
	@echo "  make man           build the CLI and emit its man page to $(BIN_DIR)/soroauth.1"
	@echo "  make vectors       regenerate testdata/vectors from the pinned reference libraries"
	@echo "  make vectors-check regenerate and fail if the committed vectors changed"
	@echo "  make diagrams      render docs/diagrams/*.dot to the committed SVGs"
	@echo "  make diagrams-check fail if the committed diagram SVGs have drifted"
	@echo "  make demo-check    check the browser demo's logic against the pinned SDK"
	@echo "  make e2e           build the test contract and run the live testnet suite"
	@echo "  make parity        run the Python stellar-sdk parity harness"
	@echo "  make parity-rust   run the Rust stellar-xdr parity harness"
	@echo "  make differential  regenerate the differential corpus and check it with JS and Python"
	@echo "  make wasm          build the js/wasm signing core into wasm/dist/"
	@echo "  make wasm-check    build the wasm core and prove it matches the golden, differential and fuzz corpora"
	@echo "  make wasm-budget   build the wasm core and fail if it is over its size ceiling"
	@echo "  make ts-test       typecheck and test the TypeScript wrapper package"
	@echo "  make jvm-test      test the JVM binding (golden replay, exceptions, loader)"
	@echo "  make jvm-native    build the JVM native library, then test with the FFM binding live"
	@echo "  make rust-test     test the Rust crate with its pins locked"
	@echo "  make grpc-test     test the gRPC service module"
	@echo "  make grpc-check    lint the proto and fail if the generated code drifted"
	@echo "  make openapi-test  run the OpenAPI conformance check against the service"
	@echo "  make openapi-check fail if the generated client drifted, then run the conformance check"
	@echo "  make action-test   build the CLI image and test the composite action (needs docker and jq)"
	@echo "  make freighter-check  check the Freighter example's logic without a browser"
	@echo "  make clean         remove $(BIN_DIR)/ and build output"

# gofmt -l prints the files that need formatting; this target turns that output
# into a failure, which is what CI's gofmt step does.
fmt:
	@unformatted="$$(gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then \
		echo "these files are not gofmt clean:"; \
		echo "$$unformatted"; \
		exit 1; \
	fi

vet:
	$(GO) vet ./...

# Per-package coverage floors (testdata/coverage/floors.json). One global floor
# let a well-covered package subsidise a thin one: the signing path was
# averaged together with the CLI and the examples, so a regression in the path
# that produces signatures could hide behind the rest. scripts/checkcov
# compares each package's statement coverage against its own floor, and the
# signing-path floors stay strictly above the 60% global floor this replaced.
# Coverage is not correctness: it says which lines ran, not that the result is
# right; the mutation-testing work is the stronger check.
coverage:
	GOTOOLCHAIN=$(COVER_TOOLCHAIN) $(GO) test -coverprofile=coverage.out -covermode=atomic ./...
	GOTOOLCHAIN=$(COVER_TOOLCHAIN) $(GO) list -f '{{.ImportPath}}' ./... > packages.txt
	GOTOOLCHAIN=$(COVER_TOOLCHAIN) $(GO) run ./scripts/checkcov coverage.out testdata/coverage/floors.json packages.txt

# A local smoke over every fuzz target: each one must start, run its seed
# corpus and fuzz for FUZZTIME without finding a crash. The continuous
# workflow (.github/workflows/fuzz.yml) runs the same targets for much longer
# every night; a finding there files an issue rather than failing here.
# Override the budget per run: `make fuzz FUZZTIME=2m`.
fuzz:
	$(GO) test -run '^$$' -fuzz FuzzValidateDelegateOrder -fuzztime $(FUZZTIME) .
	$(GO) test -run '^$$' -fuzz FuzzInspect -fuzztime $(FUZZTIME) .
	$(GO) test -run '^$$' -fuzz FuzzPreimage -fuzztime $(FUZZTIME) .
	$(GO) test -run '^$$' -fuzz FuzzPayload -fuzztime $(FUZZTIME) .
	$(GO) test -run '^$$' -fuzz FuzzDecodeAuthorizationEntry -fuzztime $(FUZZTIME) .
	$(GO) test -run '^$$' -fuzz FuzzVerifyEntry -fuzztime $(FUZZTIME) .
	$(GO) test -run '^$$' -fuzz FuzzDiffEntries -fuzztime $(FUZZTIME) .
	$(GO) test -run '^$$' -fuzz FuzzCopyRoundTrip -fuzztime $(FUZZTIME) ./internal/xdrcopy

# The long-running counterpart to the race detector: soak_test.go's
# TestSoakBatchSigning signs batches of the golden vectors from several
# goroutines, round after round, and after every round asserts the bytes still
# match the vectors and that goroutines and live heap returned to the baseline
# taken after the warm-up. It is behind the soak build tag, so no other target
# compiles it, and it is deliberately not a replacement for `go test -race`
# or TestCopyConcurrentReuse, only the same properties watched for much longer.
# The scheduled job in .github/workflows/fuzz.yml runs it for 10 minutes; the
# reported run and the measured tolerances are in docs/soak.md.
# Override the budget per run: `make soak SOAKTIME=10m`.
soak:
	$(GO) test -race -tags soak -run TestSoakBatchSigning -soak-duration $(SOAKTIME) -timeout 30m .

# Markdown is normalised so a prose diff stays about content rather than about
# re-wrapping. The formatter, its version and its config are committed
# (package.json, .prettierrc.json, .prettierignore); run `npm ci` at the
# repository root first so `npx` resolves the pinned one.
md-check:
	npx prettier --check "**/*.md"

md-format:
	npx prettier --write "**/*.md"

build:
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/soroauth

# The verification service (docs/verification-service.md). It is a separate
# binary because serving verification over a network is a deployment choice;
# the published container image stays CLI-only. The version stamp feeds
# /healthz and `soroauth-server version`.
server:
	$(GO) build -ldflags "-s -w -X main.Version=$(VERSION)" -o $(BIN_DIR)/soroauth-server ./server

# The man page is generated by the binary itself, from the same command/flag
# table the completion scripts come from, so packaging never ships a page that
# describes a flag the CLI does not accept. It is written next to the binary
# rather than into the repository root, so `make clean` removes it and a stray
# build artefact cannot be committed.
man: build
	$(BIN) man --out $(BIN_DIR)/soroauth.1
	@echo "wrote $(BIN_DIR)/soroauth.1"

# Golden vectors are generated, committed artefacts. Regenerating them is safe;
# `vectors-check` is the one that proves the committed files match, which is
# what CI runs. It also diffs testdata/frozen, the hand-committed cross-version
# set, so a `make vectors` that somehow wrote there fails the check instead of
# silently rewriting evidence that must not move.
#
# Two generators, two reference implementations: gen.mjs writes the
# authorization-entry vectors against @stellar/stellar-sdk, and gen-passkey.mjs
# writes the passkey signature-shape vectors against smart-account-kit. Both
# write under testdata/vectors, so one diff covers both.
vectors:
	cd testdata/gen && $(NPM) ci && $(NODE) gen.mjs && $(NODE) gen-passkey.mjs

vectors-check: vectors
	@if ! git diff --exit-code -- testdata/vectors testdata/frozen; then \
		echo; \
		echo "The committed golden vectors differ from freshly generated ones, or"; \
		echo "regeneration touched the frozen cross-version set under testdata/frozen."; \
		echo "Never edit a vector by hand. Commit the regenerated files with the"; \
		echo "generator change, or investigate why the reference output moved. The"; \
		echo "frozen set is never regenerated; see testdata/frozen/README.md."; \
		exit 1; \
	fi

# The browser demo needs a browser, a platform authenticator and a deployed
# passkey wallet contract on testnet, so it cannot run end to end here. This
# runs everything about it that does not, against the SDK copy testdata/gen
# pins, so an API drift in the demo fails here instead of only in a browser.
# Needs `cd testdata/gen && npm ci` first.
demo-check:
	$(NODE) examples/browser-passkey/app.test.mjs

# The e2e suite needs the contract wasm built first, and stellar-cli to build
# it. Both failures are explicit rather than a confusing test error later.
e2e:
	@command -v stellar >/dev/null 2>&1 || { \
		echo "stellar-cli 28.0.0 is required to build the e2e test contract"; \
		exit 1; \
	}
	cd e2e/contracts && stellar contract build
	$(GO) test -tags e2e -v ./e2e/...

# The Python parity harness recomputes every vector's preimage and payload with
# a third implementation. It needs its own pinned SDK, so it runs in a venv the
# target creates rather than depending on the caller's environment.
parity:
	@command -v python3 >/dev/null 2>&1 || { \
		echo "python3 is required for the parity harness"; \
		exit 1; \
	}
	python3 -m venv .venv-parity
	. .venv-parity/bin/activate && \
		pip install -q -r testdata/parity-python/requirements.txt && \
		python3 testdata/parity-python/parity.py && \
		python3 testdata/parity-python/test_parity.py

# The differential fuzzing harness. cmd/difffuzz generates a deterministic
# corpus of random entries and records this library's preimage and payload for
# each; the JS verifier and the Python parity harness (pointed at the same
# corpus) then have to reproduce every one. See
# testdata/differential/README.md.
#
# Regenerating the corpus must not change the committed files: if it does, the
# generator moved and the regenerated corpus belongs in the same commit. The
# check mirrors vectors-check.
differential:
	@command -v python3 >/dev/null 2>&1 || { \
		echo "python3 is required for the differential harness"; \
		exit 1; \
	}
	go run ./cmd/difffuzz
	@if ! git diff --exit-code -- testdata/differential/corpus; then \
		echo; \
		echo "The committed differential corpus differs from freshly generated cases."; \
		echo "Never edit a case by hand. Commit the regenerated corpus with the"; \
		echo "generator change, or investigate why the recording moved."; \
		exit 1; \
	fi
	cd testdata/differential && $(NPM) ci && $(NODE) verify.mjs
	python3 -m venv .venv-parity
	. .venv-parity/bin/activate && \
		pip install -q -r testdata/parity-python/requirements.txt && \
		python3 testdata/parity-python/parity.py --vectors testdata/differential/corpus && \
		if ls testdata/differential/regressions/*.json >/dev/null 2>&1; then \
			python3 testdata/parity-python/parity.py --vectors testdata/differential/regressions; \
		fi

# The Rust parity harness recomputes every vector's preimage and payload with
# the stellar-xdr crate, the same XDR implementation the Soroban host uses. The
# crate is pinned exactly in Cargo.toml and Cargo.lock, and --locked makes the
# committed lock authoritative instead of letting cargo re-resolve.
parity-rust:
	@command -v cargo >/dev/null 2>&1 || { \
		echo "cargo (Rust 1.93.0) is required for the Rust parity harness"; \
		exit 1; \
	}
	cd testdata/parity-rust && cargo test --locked && cargo run --locked --bin parity

# The diagrams in docs/ are committed twice: the Graphviz source and the
# rendered SVG. `diagrams` rewrites the SVGs; `diagrams-check` fails if they no
# longer match their sources, which is what CI runs. Never edit an SVG by hand
# (docs/diagrams/README.md).
diagrams:
	node docs/diagrams/render.mjs

diagrams-check:
	node docs/diagrams/render.mjs --check

wasm:
	./wasm/build.sh

# Builds the module and then replays the golden vectors, the differential corpus
# (and its frozen regressions) and the fuzz seed corpus through it, asserting
# byte-identical output against the native build.
wasm-check: wasm
	$(NODE) wasm/parity.mjs

ts-test: wasm
	cd wasm/ts && $(NPM) ci && $(NPM) run typecheck && $(NPM) test

# The JVM binding (bindings/jvm): the golden vectors replayed through the
# JVM API with byte equality, the exception distinctions, and the native
# selection mechanism. Needs Maven and JDK 22+, the binding's stated
# minimum; no Go or Rust toolchain beyond what the checkout already needs.
jvm-test:
	cd bindings/jvm && mvn -B test

# jvm-test plus the FFM binding live: builds the native library for the
# host platform into the resources tree first, so NativeSoroauthTest links
# it instead of skipping. Needs a C toolchain for cgo.
jvm-native:
	cd bindings/jvm/native && ./build.sh
	cd bindings/jvm && mvn -B test

# The Rust crate (bindings/rust): every golden vector with byte equality,
# against the locked pins. Needs Rust 1.93.0 (rustup fetches it from
# bindings/rust/rust-toolchain.toml).
rust-test:
	cd bindings/rust && cargo test --locked

# The gRPC service (integrations/grpc): parity with the HTTP surfaces, the
# honesty boundary, and deadline propagation. A module of its own, so this
# runs in its directory rather than under the root ./....
grpc-test:
	cd integrations/grpc && $(GO) vet ./... && $(GO) test -race ./...

# The schema sync gate: buf lint plus regeneration, failing when the
# committed gen/ differs from what the schema produces. Needs buf and the
# pinned protoc-gen-go plugins (see integrations/grpc/generate.sh).
grpc-check:
	cd integrations/grpc && buf lint && ./generate.sh && git diff --exit-code -- gen/

# The Freighter example's logic (examples/wallet-freighter): classification,
# wrong-network detection, and the verify-before-use gate. Needs only Node;
# no browser and no wallet extension.
freighter-check:
	$(NODE) examples/wallet-freighter/app.test.mjs

# The verification service's OpenAPI spec and conformance check
# (server/openapi/README.md). The check builds and drives the real service and
# validates every response against the committed document, so it is a module of
# its own and runs in its directory rather than under the root ./....
openapi-test:
	cd server/openapi && $(GO) test -race ./...

# The spec sync gate the gRPC module also has: regenerating the client must be
# a no-op, and then the running service must match the document. This is what
# CI runs; openapi-test is the same check without the regeneration diff.
openapi-check:
	cd server/openapi && ./generate.sh && git diff --exit-code -- client/
	cd server/openapi && $(GO) vet ./... && $(GO) test -race ./...

# The composite action (integrations/action): its own integration test, the
# same one .github/workflows/ci-action.yml runs. It builds the CLI image the
# action runs, then proves the action passes a signed entry, fails an unsigned
# one, and fails a wrong expected arm. Needs docker to run the CLI and jq to
# lift the two vectors out of the committed golden file.
action-test:
	@command -v docker >/dev/null 2>&1 || { echo "docker is required for action-test"; exit 1; }
	@command -v jq >/dev/null 2>&1 || { echo "jq is required for action-test"; exit 1; }
	docker build -t soroauth-action:ci .
	@set -e; \
	signed="$$(jq -r .signed_entry_xdr testdata/vectors/v2_single_testnet.json)"; \
	unsigned="$$(jq -r .unsigned_entry_xdr testdata/vectors/v2_single_testnet.json)"; \
	echo "--- a good entry passes ---"; \
	SOROAUTH_INPUT_ENTRY="$$signed" SOROAUTH_INPUT_NETWORK=testnet \
		SOROAUTH_INPUT_EXPECTED_ARM=address_v2 SOROAUTH_INPUT_IMAGE=soroauth-action:ci \
		bash integrations/action/verify.sh; \
	echo "--- a bad entry fails ---"; \
	if SOROAUTH_INPUT_ENTRY="$$unsigned" SOROAUTH_INPUT_NETWORK=testnet \
		SOROAUTH_INPUT_IMAGE=soroauth-action:ci \
		bash integrations/action/verify.sh; then \
		echo "the action passed an unsigned entry that must fail"; \
		exit 1; \
	fi; \
	echo "--- a wrong expected arm fails ---"; \
	if SOROAUTH_INPUT_ENTRY="$$signed" SOROAUTH_INPUT_NETWORK=testnet \
		SOROAUTH_INPUT_EXPECTED_ARM=source_account SOROAUTH_INPUT_IMAGE=soroauth-action:ci \
		bash integrations/action/verify.sh; then \
		echo "the action passed an entry whose arm did not match expected-arm"; \
		exit 1; \
	fi; \
	echo "action-test: ok"

# Builds the module and measures it against the 3 MiB ceiling, failing if it is
# over. The core is downloaded by a browser, so its size is a property worth
# failing on rather than noticing later.
wasm-budget: build wasm
	$(BIN_DIR)/soroauth wasm-budget --out wasm/dist/soroauth.wasm

clean:
	rm -rf $(BIN_DIR) wasm/dist wasm/ts/dist wasm/ts/node_modules .venv-parity
