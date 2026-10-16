// Command gencorpus builds the fuzz seed corpora for all fuzz targets
// from the committed golden vectors.
//
// Why generate it rather than hand-write seeds: the golden vectors are the
// entries this library is proven against, so they are exactly the inputs a
// fuzzer should start from — every credential arm, a sub-invocation tree, a
// create-contract invocation, the int64 nonce edges, and three delegate shapes
// including one address at two nesting depths. Starting the fuzzer from real
// entries means its mutations begin inside the space of things that decode,
// instead of spending the budget discovering what a valid entry looks like.
//
// Three details about the output are not free choices:
//
//   - The directory is testdata/fuzz/<TargetName>. Go reads a
//     target's seed corpus from testdata/fuzz/<TargetName>, and only from
//     there; files anywhere else, including directly in testdata/fuzz, are
//     ignored.
//   - The file format is Go's corpus format — the "go test fuzz v1" header
//     followed by one Go literal per fuzz argument — not the raw bytes. A file
//     in that directory that is not in this format fails the package's tests
//     rather than being skipped.
//   - Cleanup is manifest-tracked, not RemoveAll. A fuzzer that finds a crash
//     writes the reproducer into testdata/fuzz/<TargetName>, and that file is
//     committed as a regression seed — so gencorpus must never delete a file
//     it did not write. Each target's generated filenames are recorded in
//     testdata/fuzz/.gencorpus/<TargetName>, and only those files are removed
//     before rewriting. Anything else in the seed directory is left alone.
//
// The seed is the decoded entry, not the base64 text, because the target's
// argument is the []byte it hands to UnmarshalBinary. The one two-input target,
// FuzzDiffEntries, gets a pair of decoded entries per seed — the entry against
// itself, and against a tampered variant — written by the same generator so the
// pair corpus is held to the same drift check as the rest.
//
// It also writes testdata/wasm-parity/fuzz_expectations.json: the native result
// for every seed, which wasm/parity.mjs replays the wasm build against. The wasm
// core exposes only preimage and payload, so those are the two operations
// recorded; an entry-shaped seed is recorded as a preimage case and a
// FuzzPayload seed as a payload case. Recording the native bytes here rather
// than recomputing them in the harness keeps one definition of the operation
// and lets the existing regenerate-and-diff check cover the expectations too.
//
// Run from the repository root:
//
//	go run ./cmd/gencorpus
//
// It is deterministic: the same vectors produce byte-identical corpus files and
// expectations, so CI regenerates and fails on drift the same way it does for
// the vectors.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	soroauth "github.com/soroauth/soroauth-go"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"
)

const (
	vectorsDir = "testdata/vectors"
	fuzzDir    = "testdata/fuzz"
	// manifestDir records, per fuzz target, the seed filenames gencorpus
	// generated. It lives outside the seed directories because Go treats
	// every file inside testdata/fuzz/<TargetName> as a seed: a manifest
	// there would fail the package's tests instead of being skipped.
	manifestDir = "testdata/fuzz/.gencorpus"
	// expectationsPath is the native-side record wasm/parity.mjs replays the
	// wasm build against. It is generated, committed and drift-checked with
	// the seeds it describes, so the two can never name different bytes.
	expectationsPath = "testdata/wasm-parity/fuzz_expectations.json"

	// These mirror the constants the fuzz targets use (preimage_test.go) and
	// the values the wasm harness passes when it replays a seed. They are
	// written into the expectations file so the harness does not hardcode them.
	testValidUntilLedger  = uint32(1234567)
	testNetworkPassphrase = network.TestNetworkPassphrase
)

// vector is the part of a golden vector this reads: the entry before any
// delegate wrapping, the entry as it goes to the signer, and the finished
// signed entry. All three are entries the fuzz targets can decode, and
// pre_wrap_entry_xdr is absent from most vectors. signed_entry_xdr is used by
// the pair target, where a signature left in place over a moved payload is the
// case worth starting from.
type vector struct {
	PreWrapEntryXDR  string `json:"pre_wrap_entry_xdr"`
	UnsignedEntryXDR string `json:"unsigned_entry_xdr"`
	SignedEntryXDR   string `json:"signed_entry_xdr"`
}

// targets is the list of fuzz targets that take a single entry as input.
var targets = []string{
	"FuzzValidateDelegateOrder",
	"FuzzInspect",
	"FuzzPreimage",
	"FuzzDecodeAuthorizationEntry",
	"FuzzVerifyEntry",
}

// pairTarget is the one fuzz target that takes two entries. Its seeds carry two
// []byte literals, one per argument, so they are written by writePairSeeds
// rather than the single-input loop above and are listed in the expectations as
// not replayed: the wasm core decodes and hashes one entry at a time and has no
// DiffEntries surface to replay a pair through.
const pairTarget = "FuzzDiffEntries"

// fuzzOperation maps a fuzz target's seed directory to the wasm entry point its
// seeds are replayed through by wasm/parity.mjs. The wasm core exposes only
// preimage and payload, so an entry-shaped seed (every target but FuzzPayload)
// is replayed through preimage; FuzzPayload's raw bytes are a HashIdPreimage and
// are replayed through payload. The mapping is recorded per case, not inferred
// from the target name, so the harness never has to duplicate it.
var fuzzOperation = map[string]string{
	"FuzzValidateDelegateOrder":    "preimage",
	"FuzzInspect":                  "preimage",
	"FuzzPreimage":                 "preimage",
	"FuzzDecodeAuthorizationEntry": "preimage",
	"FuzzVerifyEntry":              "preimage",
	"FuzzPayload":                  "payload",
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "gencorpus: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	entries, err := os.ReadDir(vectorsDir)
	if err != nil {
		return fmt.Errorf("reading %s: %w", vectorsDir, err)
	}

	// Sorted, so the output does not depend on directory order.
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return fmt.Errorf("no vectors found in %s; run this from the repository root", vectorsDir)
	}

	totalWritten := 0
	for _, target := range targets {
		outDir := filepath.Join(fuzzDir, target)

		if err := os.MkdirAll(outDir, 0o755); err != nil {
			return fmt.Errorf("creating %s: %w", outDir, err)
		}
		// Remove only what the previous run generated — a stale seed whose
		// vector was deleted or renamed. Anything else in the directory is
		// a committed crash reproducer and is left alone.
		generated := manifestNames(filepath.Join(manifestDir, target))
		for _, name := range generated {
			if err := os.Remove(filepath.Join(outDir, name)); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("clearing %s: %w", filepath.Join(outDir, name), err)
			}
		}

		written := 0
		var writtenNames []string
		for _, name := range names {
			path := filepath.Join(vectorsDir, name)
			raw, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("reading %s: %w", path, err)
			}

			var v vector
			if err := json.Unmarshal(raw, &v); err != nil {
				return fmt.Errorf("parsing %s: %w", path, err)
			}

			// A malformed vector is an error, not something to skip: a silently
			// skipped vector is a seed the fuzzer never gets, and nothing would
			// say so.
			stem := name[:len(name)-len(".json")]
			for i, encoded := range []string{v.UnsignedEntryXDR, v.PreWrapEntryXDR} {
				if encoded == "" {
					continue
				}
				decoded, err := base64.StdEncoding.DecodeString(encoded)
				if err != nil {
					return fmt.Errorf("decoding entry %d of %s: %w", i, path, err)
				}
				seedName := fmt.Sprintf("%s_%d", stem, i)
				outPath := filepath.Join(outDir, seedName)
				if err := os.WriteFile(outPath, corpusFile(decoded), 0o644); err != nil {
					return fmt.Errorf("writing %s: %w", outPath, err)
				}
				writtenNames = append(writtenNames, seedName)
				written++
			}
		}
		if err := writeManifest(target, writtenNames); err != nil {
			return fmt.Errorf("writing the %s manifest: %w", target, err)
		}

		fmt.Printf("wrote %d seeds for %s into %s\n", written, target, outDir)
		totalWritten += written
	}

	// FuzzPayload takes []byte as input but doesn't use entry XDR.
	// We add some basic payload seeds separately.
	if err := writePayloadSeeds(); err != nil {
		return fmt.Errorf("writing payload seeds: %w", err)
	}

	// The two-input DiffEntries target: entry pairs built from the vectors and
	// their tampered variants.
	pairWritten, err := writePairSeeds(names)
	if err != nil {
		return fmt.Errorf("writing %s seeds: %w", pairTarget, err)
	}
	totalWritten += pairWritten

	// Record the native result for every seed now on disk, including a
	// committed crash reproducer gencorpus did not write. Done last, after
	// every seed directory is populated, so the expectations always describe
	// the exact set of seeds the fuzzer and the wasm harness both read.
	recorded, err := writeExpectations()
	if err != nil {
		return fmt.Errorf("writing wasm parity expectations: %w", err)
	}

	fmt.Printf("total seeds written: %d\n", totalWritten)
	fmt.Printf("recorded native expectations for %d seeds in %s\n", recorded, expectationsPath)
	return nil
}

// corpusFile renders one seed in Go's fuzz corpus format: the version header,
// then one Go literal per argument of the fuzz function. Most targets take a
// single []byte, so there is one literal; FuzzDiffEntries takes two and gets
// two, one per line.
func corpusFile(args ...[]byte) []byte {
	var b strings.Builder
	b.WriteString("go test fuzz v1\n")
	for _, arg := range args {
		b.WriteString("[]byte(")
		b.WriteString(strconv.Quote(string(arg)))
		b.WriteString(")\n")
	}
	return []byte(b.String())
}

// writePairSeeds builds the seed corpus for the two-input DiffEntries target.
// For each golden vector it pairs the entry against itself (the identical
// case), the signed entry against the same entry with its signature expiration
// advanced (the stale-signature case: the payload moves while the signature
// stays put), and the unsigned entry against its delegate-wrapped form where
// the vector has one. Every pair is drawn from bytes the golden vectors already
// commit, so the fuzzer mutates from real entries rather than discovering their
// shape. The pair files carry two []byte literals, which is why they are
// written here and not by the single-input loop.
func writePairSeeds(names []string) (int, error) {
	outDir := filepath.Join(fuzzDir, pairTarget)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return 0, fmt.Errorf("creating %s: %w", outDir, err)
	}
	if err := clearGenerated(outDir, pairTarget); err != nil {
		return 0, err
	}

	type pair struct {
		name string
		a, b []byte
	}
	var pairs []pair
	for _, name := range names {
		path := filepath.Join(vectorsDir, name)
		raw, err := os.ReadFile(path)
		if err != nil {
			return 0, fmt.Errorf("reading %s: %w", path, err)
		}
		var v vector
		if err := json.Unmarshal(raw, &v); err != nil {
			return 0, fmt.Errorf("parsing %s: %w", path, err)
		}
		stem := name[:len(name)-len(".json")]

		unsigned, err := decodeEntry(v.UnsignedEntryXDR, path)
		if err != nil {
			return 0, err
		}
		preWrap, err := decodeEntry(v.PreWrapEntryXDR, path)
		if err != nil {
			return 0, err
		}
		signed, err := decodeEntry(v.SignedEntryXDR, path)
		if err != nil {
			return 0, err
		}

		if len(unsigned) > 0 {
			pairs = append(pairs, pair{name: stem + "_identical", a: unsigned, b: unsigned})
		}
		if len(signed) > 0 {
			pairs = append(pairs, pair{name: stem + "_signed_identical", a: signed, b: signed})
			if tampered, ok := movedExpiration(signed); ok {
				pairs = append(pairs, pair{name: stem + "_signed_stale", a: signed, b: tampered})
			}
		}
		if len(unsigned) > 0 && len(preWrap) > 0 && !bytes.Equal(unsigned, preWrap) {
			pairs = append(pairs, pair{name: stem + "_prewrap", a: unsigned, b: preWrap})
		}
	}

	var writtenNames []string
	for _, p := range pairs {
		outPath := filepath.Join(outDir, p.name)
		if err := os.WriteFile(outPath, corpusFile(p.a, p.b), 0o644); err != nil {
			return 0, fmt.Errorf("writing %s: %w", outPath, err)
		}
		writtenNames = append(writtenNames, p.name)
	}
	if err := writeManifest(pairTarget, writtenNames); err != nil {
		return 0, fmt.Errorf("writing the %s manifest: %w", pairTarget, err)
	}

	fmt.Printf("wrote %d seeds for %s into %s\n", len(pairs), pairTarget, outDir)
	return len(pairs), nil
}

// clearGenerated removes the files a previous run recorded in the target's
// manifest, leaving anything else — in particular a committed crash reproducer
// sharing the directory — untouched.
func clearGenerated(outDir, target string) error {
	for _, name := range manifestNames(filepath.Join(manifestDir, target)) {
		if err := os.Remove(filepath.Join(outDir, name)); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("clearing %s: %w", filepath.Join(outDir, name), err)
		}
	}
	return nil
}

// decodeEntry decodes an optional base64 entry, returning nil for a field the
// vector omits. name is only used in the error message.
func decodeEntry(encoded, name string) ([]byte, error) {
	if encoded == "" {
		return nil, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decoding an entry of %s: %w", name, err)
	}
	return decoded, nil
}

// movedExpiration deep-copies an address-credentialed entry and advances its
// signature expiration ledger by one, so the preimage and payload move while
// whatever signature the entry carries stays put — the stale-signature pair the
// diff has to report. It reports false for a source-account entry, which has no
// such field.
func movedExpiration(encoded []byte) ([]byte, bool) {
	var entry xdr.SorobanAuthorizationEntry
	if err := entry.UnmarshalBinary(encoded); err != nil {
		return nil, false
	}

	var credentials *xdr.SorobanAddressCredentials
	switch entry.Credentials.Type {
	case xdr.SorobanCredentialsTypeSorobanCredentialsAddress:
		credentials = entry.Credentials.Address
	case xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2:
		credentials = entry.Credentials.AddressV2
	case xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates:
		if entry.Credentials.AddressWithDelegates != nil {
			credentials = &entry.Credentials.AddressWithDelegates.AddressCredentials
		}
	}
	if credentials == nil {
		return nil, false
	}

	credentials.SignatureExpirationLedger++
	tampered, err := entry.MarshalBinary()
	if err != nil {
		return nil, false
	}
	return tampered, true
}

func writePayloadSeeds() error {
	target := "FuzzPayload"
	outDir := filepath.Join(fuzzDir, target)

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", outDir, err)
	}
	generated := manifestNames(filepath.Join(manifestDir, target))
	for _, name := range generated {
		if err := os.Remove(filepath.Join(outDir, name)); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("clearing %s: %w", filepath.Join(outDir, name), err)
		}
	}

	seeds := [][]byte{
		{0},
		{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
		{0x01, 0x02, 0x03, 0x04},
		{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	}

	var writtenNames []string
	for i, seed := range seeds {
		seedName := fmt.Sprintf("seed_%d", i)
		outPath := filepath.Join(outDir, seedName)
		if err := os.WriteFile(outPath, corpusFile(seed), 0o644); err != nil {
			return fmt.Errorf("writing %s: %w", outPath, err)
		}
		writtenNames = append(writtenNames, seedName)
	}
	if err := writeManifest(target, writtenNames); err != nil {
		return fmt.Errorf("writing the %s manifest: %w", target, err)
	}

	fmt.Printf("wrote %d seeds for %s into %s\n", len(seeds), target, outDir)
	return nil
}

// manifestNames reads the filenames a previous run recorded for a target.
// A missing manifest is not an error: it means nothing was generated yet,
// e.g. the first run after this tracking was added.
func manifestNames(path string) []string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var names []string
	for _, line := range strings.Split(string(raw), "\n") {
		if line != "" {
			names = append(names, line)
		}
	}
	return names
}

// writeManifest records the seed filenames a run generated, sorted so the
// file is deterministic. The next run deletes exactly these files before
// rewriting, which is what lets a stale seed disappear without touching a
// committed crash reproducer sharing the directory.
func writeManifest(target string, names []string) error {
	sort.Strings(names)
	if err := os.MkdirAll(manifestDir, 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", manifestDir, err)
	}
	body := ""
	if len(names) > 0 {
		body = strings.Join(names, "\n") + "\n"
	}
	if err := os.WriteFile(filepath.Join(manifestDir, target), []byte(body), 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", filepath.Join(manifestDir, target), err)
	}
	return nil
}

// expectation is the native result for one seed: the operation the seed is
// replayed through, and either the bytes that operation produced or the fact
// that the native build refused the input. A rejected seed is not skipped: the
// harness requires the wasm build to refuse it too, so a decode that starts
// succeeding in wasm fails the run.
type expectation struct {
	Operation   string `json:"operation"`
	Status      string `json:"status"`
	PreimageXDR string `json:"preimage_xdr,omitempty"`
	PayloadHex  string `json:"payload_hex,omitempty"`
}

// expectationsFile is the on-disk document wasm/parity.mjs reads.
type expectationsFile struct {
	SchemaVersion     int    `json:"schema_version"`
	Note              string `json:"note"`
	ValidUntilLedger  uint32 `json:"valid_until_ledger"`
	NetworkPassphrase string `json:"network_passphrase"`
	// NonReplayedTargets names seed directories the harness must not require a
	// replay expectation for. FuzzDiffEntries takes two entries per seed and
	// the wasm core exposes no pair surface, so its seeds are generated for
	// the native fuzzer only. Keeping the list in the document, rather than
	// hardcoding it in the harness, means the two cannot disagree about which
	// target that is.
	NonReplayedTargets []string `json:"non_replayed_targets"`
	// Cases is keyed by "<Target>/<seed file name>", the same key the harness
	// derives from the seed corpus, so a seed and its expectation cannot drift.
	Cases map[string]expectation `json:"cases"`
}

// writeExpectations reads every seed on disk and records the native result.
// Reading the directory rather than remembering what was written means a
// committed crash reproducer is recorded too; a seed with no expectation would
// otherwise be a case the harness silently skips.
func writeExpectations() (int, error) {
	cases := make(map[string]expectation)
	for target, operation := range fuzzOperation {
		outDir := filepath.Join(fuzzDir, target)
		entries, err := os.ReadDir(outDir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return 0, fmt.Errorf("reading %s: %w", outDir, err)
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			data, err := readSeedFile(filepath.Join(outDir, e.Name()))
			if err != nil {
				return 0, fmt.Errorf("reading seed %s/%s: %w", target, e.Name(), err)
			}
			cases[target+"/"+e.Name()] = expectationFor(operation, data)
		}
	}

	doc := expectationsFile{
		SchemaVersion:      2,
		Note:               "Native Go results for the fuzz seed corpus, replayed by wasm/parity.mjs. Generated by cmd/gencorpus; never edit by hand. Status \"reject\" means the native build refused the input and the wasm build must refuse it too. Targets in non_replayed_targets take more than one entry per seed; the wasm core has no surface to replay them through, so they are native-only.",
		ValidUntilLedger:   testValidUntilLedger,
		NetworkPassphrase:  testNetworkPassphrase,
		NonReplayedTargets: []string{pairTarget},
		Cases:              cases,
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return 0, fmt.Errorf("marshalling expectations: %w", err)
	}
	raw = append(raw, '\n')
	if err := os.MkdirAll(filepath.Dir(expectationsPath), 0o755); err != nil {
		return 0, fmt.Errorf("creating %s: %w", filepath.Dir(expectationsPath), err)
	}
	if err := os.WriteFile(expectationsPath, raw, 0o644); err != nil {
		return 0, fmt.Errorf("writing %s: %w", expectationsPath, err)
	}
	return len(cases), nil
}

// readSeedFile parses the raw []byte out of a single-input Go fuzz corpus file.
// Every seed of a target in fuzzOperation has exactly one []byte literal on the
// second line, and so does every reproducer the Go fuzzer writes. The two-input
// DiffEntries target is not in fuzzOperation and is never read here.
func readSeedFile(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.SplitN(string(raw), "\n", 3)
	if len(lines) < 2 || lines[0] != "go test fuzz v1" {
		return nil, fmt.Errorf("not a Go fuzz corpus file (missing %q header)", "go test fuzz v1")
	}
	literal := strings.TrimSpace(lines[1])
	const prefix = "[]byte("
	if !strings.HasPrefix(literal, prefix) || !strings.HasSuffix(literal, ")") {
		return nil, fmt.Errorf("unsupported argument literal %q", literal)
	}
	unquoted, err := strconv.Unquote(literal[len(prefix) : len(literal)-1])
	if err != nil {
		return nil, fmt.Errorf("unquoting argument: %w", err)
	}
	return []byte(unquoted), nil
}

// expectationFor computes the native result for one seed, using exactly the
// decode and the two operations the wasm binding uses (cmd/soroauthwasm):
// SafeUnmarshalBase64 into an entry or a HashIdPreimage, then Preimage/Payload.
// Mirroring the binding rather than a stricter path means a mismatch the
// harness reports is a difference between the two builds, not a difference
// between two call sites.
func expectationFor(operation string, data []byte) expectation {
	b64 := base64.StdEncoding.EncodeToString(data)
	if operation == "payload" {
		var pre xdr.HashIdPreimage
		if err := xdr.SafeUnmarshalBase64(b64, &pre); err != nil {
			return expectation{Operation: operation, Status: "reject"}
		}
		digest, err := soroauth.Payload(pre)
		if err != nil {
			return expectation{Operation: operation, Status: "reject"}
		}
		return expectation{Operation: operation, Status: "ok", PayloadHex: hex.EncodeToString(digest[:])}
	}

	var entry xdr.SorobanAuthorizationEntry
	if err := xdr.SafeUnmarshalBase64(b64, &entry); err != nil {
		return expectation{Operation: operation, Status: "reject"}
	}
	pre, err := soroauth.Preimage(entry, testValidUntilLedger, testNetworkPassphrase)
	if err != nil {
		return expectation{Operation: operation, Status: "reject"}
	}
	raw, err := pre.MarshalBinary()
	if err != nil {
		return expectation{Operation: operation, Status: "reject"}
	}
	digest, err := soroauth.Payload(pre)
	if err != nil {
		return expectation{Operation: operation, Status: "reject"}
	}
	return expectation{
		Operation:   operation,
		Status:      "ok",
		PreimageXDR: base64.StdEncoding.EncodeToString(raw),
		PayloadHex:  hex.EncodeToString(digest[:]),
	}
}
