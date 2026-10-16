package soroauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// signVectorEntry replays a golden vector's signing steps onto its unsigned
// entry, so the verification tests below and golden_test.go agree on what the
// "signed" entry for a vector is.
func signVectorEntry(t *testing.T, v vector) xdr.SorobanAuthorizationEntry {
	t.Helper()

	var entry xdr.SorobanAuthorizationEntry
	if err := xdr.SafeUnmarshalBase64(v.UnsignedEntryXDR, &entry); err != nil {
		t.Fatalf("decoding the unsigned entry: %v", err)
	}

	signed := entry
	for i, step := range v.Steps {
		var opts []AuthorizeOption
		if step.ForAddress != nil {
			opts = append(opts, ForAddress(*step.ForAddress))
		}
		var err error
		signed, err = AuthorizeEntry(context.Background(), signed,
			signerForLabel(t, step.SignerLabel), v.ValidUntilLedger, v.NetworkPassphrase, opts...)
		if err != nil {
			t.Fatalf("step %d (%s): %v", i, step.SignerLabel, err)
		}
	}
	return signed
}

// TestVerifyEntryGoldenVectors runs the engine over every signed golden vector.
// This is the evidence that offline verification agrees with the entries the
// reference implementation produced.
//
// Every node must come back verified or unsigned; a vector must never produce
// an invalid or cannot-check verdict, because every vector is a classic
// account signature laid out by the JS reference. The delegates vectors are the
// interesting case: their top-level node is deliberately Void (CAP-71-01), so
// it must be reported unsigned while every delegate verifies.
func TestVerifyEntryGoldenVectors(t *testing.T) {
	for _, v := range loadVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			var entry xdr.SorobanAuthorizationEntry
			if err := xdr.SafeUnmarshalBase64(v.UnsignedEntryXDR, &entry); err != nil {
				t.Fatalf("decoding the unsigned entry: %v", err)
			}

			// The source-account arm has no payload of its own; the report
			// must say so rather than pretend to have checked something.
			if entry.Credentials.Type == xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount {
				report, err := VerifyEntry(entry, v.NetworkPassphrase)
				if err != nil {
					t.Fatalf("VerifyEntry: %v", err)
				}
				if len(report.Nodes) != 0 {
					t.Fatalf("source-account entry reported %d nodes, want 0", len(report.Nodes))
				}
				if report.Note == "" {
					t.Error("source-account entry reported no note explaining there is nothing to verify")
				}
				if !report.Verified() {
					t.Error("source-account entry verified false; it has nothing that can fail")
				}
				return
			}

			signed := signVectorEntry(t, v)

			// The engine must rebuild the payload from the entry's own stored
			// expiration, which is what the vector recorded.
			report, err := VerifyEntry(signed, v.NetworkPassphrase)
			if err != nil {
				t.Fatalf("VerifyEntry: %v", err)
			}

			if report.ValidUntilLedger != v.ValidUntilLedger {
				t.Errorf("rebuilt over expiration %d, want the entry's stored %d",
					report.ValidUntilLedger, v.ValidUntilLedger)
			}
			if len(report.Nodes) == 0 {
				t.Fatal("entry reported no credential nodes")
			}

			// Which addresses the vector's own steps signed decides each node's
			// expected verdict, so the assertion is derived from the case rather
			// than assuming every delegate was signed. In the two-levels vector
			// one address is signed once and fills both of its nodes, while the
			// other delegate is deliberately left unsigned.
			wantVerified := signedAddresses(t, v)
			for i, node := range report.Nodes {
				want := VerdictUnsigned
				if wantVerified[node.Address] {
					want = VerdictVerified
				}
				if node.Verdict != want {
					t.Errorf("node %d (%s) verdict %q (%s), want %q",
						i, node.Address, node.Verdict, node.Reason, want)
				}
			}

			// The report must never call a golden vector invalid or
			// cannot-check: every vector's nodes are classic account signatures.
			for i, node := range report.Nodes {
				if node.Verdict == VerdictInvalid || node.Verdict == VerdictCannotCheck {
					t.Errorf("node %d (%s) verdict %q (%s); a golden vector must never be %q or %q",
						i, node.Address, node.Verdict, node.Reason, VerdictInvalid, VerdictCannotCheck)
				}
			}

			// A delegates vector's top-level node is Void (CAP-71-01), so it
			// must never read as verified.
			if entry.Credentials.Type == xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates {
				if report.Nodes[0].Verdict != VerdictUnsigned {
					t.Errorf("delegates vector top-level node verdict %q, want %q (its signature is Void)",
						report.Nodes[0].Verdict, VerdictUnsigned)
				}
				if len(report.Nodes) < 2 {
					t.Fatalf("delegates vector reported %d nodes, want at least a top-level and a delegate", len(report.Nodes))
				}
			}

			if report.Verified() != allNodesVerified(t, v) {
				t.Errorf("Verified() = %v, want %v", report.Verified(), allNodesVerified(t, v))
			}
		})
	}
}

// signedAddresses returns the set of addresses a vector's steps signed: the
// explicit for_address when one was given, otherwise the signer's own address.
func signedAddresses(t *testing.T, v vector) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, step := range v.Steps {
		if step.ForAddress != nil {
			out[*step.ForAddress] = true
			continue
		}
		kp, err := keypair.FromRawSeed(sha256.Sum256([]byte(step.SignerLabel)))
		if err != nil {
			t.Fatalf("deriving the keypair for %q: %v", step.SignerLabel, err)
		}
		out[kp.Address()] = true
	}
	return out
}

// allNodesVerified reports whether every credential node a vector has is in
// the set its steps signed, and there is at least one such node.
func allNodesVerified(t *testing.T, v vector) bool {
	t.Helper()
	if len(signedAddresses(t, v)) == 0 {
		return false
	}
	var entry xdr.SorobanAuthorizationEntry
	if err := xdr.SafeUnmarshalBase64(v.UnsignedEntryXDR, &entry); err != nil {
		t.Fatalf("decoding the unsigned entry: %v", err)
	}
	signed := signVectorEntry(t, v)
	nodes, err := credentialNodes(&signed)
	if err != nil {
		t.Fatalf("credentialNodes: %v", err)
	}
	want := signedAddresses(t, v)
	for _, node := range nodes {
		address, err := formatAddressBytes(node.encoded)
		if err != nil {
			t.Fatalf("formatAddressBytes: %v", err)
		}
		if !want[address] {
			return false
		}
	}
	return len(nodes) > 0
}

// TestVerifyEntryCoversLegacyAndV2 exercises the engine directly on the two
// single-node address arms, including the address-bound flag each arm reports.
func TestVerifyEntryCoversLegacyAndV2(t *testing.T) {
	tests := []struct {
		name      string
		armType   xdr.SorobanCredentialsType
		wantBound bool
	}{
		{name: "legacy", armType: xdr.SorobanCredentialsTypeSorobanCredentialsAddress, wantBound: false},
		{name: "v2", armType: xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, wantBound: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry, signer := signedEntryFixture(t, tt.armType)
			signed, err := AuthorizeEntry(context.Background(), entry, signer, testValidUntilLedger, network.TestNetworkPassphrase)
			if err != nil {
				t.Fatalf("AuthorizeEntry: %v", err)
			}

			report, err := VerifyEntry(signed, network.TestNetworkPassphrase)
			if err != nil {
				t.Fatalf("VerifyEntry: %v", err)
			}
			if report.AddressBound != tt.wantBound {
				t.Errorf("AddressBound = %v, want %v", report.AddressBound, tt.wantBound)
			}
			if len(report.Nodes) != 1 || report.Nodes[0].Verdict != VerdictVerified {
				t.Fatalf("got %+v, want a single verified node", report.Nodes)
			}
			if !report.Verified() {
				t.Error("Verified() = false for a correctly signed entry")
			}
		})
	}
}

// TestVerifyEntryRejectsATamperedSignature is the guard that makes the engine
// worth having: a signature that is present and well-formed but wrong must be
// reported invalid, not verified.
func TestVerifyEntryRejectsATamperedSignature(t *testing.T) {
	entry, signer := signedEntryFixture(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2)
	signed, err := AuthorizeEntry(context.Background(), entry, signer, testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("AuthorizeEntry: %v", err)
	}

	credentials, err := addressCredentials(signed.Credentials)
	if err != nil {
		t.Fatalf("addressCredentials: %v", err)
	}
	publicKey, signature, err := parseAccountSignature(credentials.Signature)
	if err != nil {
		t.Fatalf("parseAccountSignature: %v", err)
	}

	// Flip one bit of the signature, leaving the public key and shape intact.
	tampered := append([]byte(nil), signature...)
	tampered[0] ^= 0x01
	credentials.Signature = scVec(accountSignature(publicKey, tampered))

	report, err := VerifyEntry(signed, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("VerifyEntry: %v", err)
	}
	if len(report.Nodes) != 1 {
		t.Fatalf("got %d nodes, want 1", len(report.Nodes))
	}
	if report.Nodes[0].Verdict != VerdictInvalid {
		t.Errorf("verdict = %q (%s), want %q", report.Nodes[0].Verdict, report.Nodes[0].Reason, VerdictInvalid)
	}
	if report.Verified() {
		t.Error("a tampered signature reported Verified true")
	}
}

// TestVerifyEntryCannotCheckCustomShapes proves the fail-closed rule: a
// signature this engine does not recognise is reported as cannot-check, never
// as verified, and the reason names the contract as the authority.
func TestVerifyEntryCannotCheckCustomShapes(t *testing.T) {
	entry, signer := signedEntryFixture(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2)
	signed, err := AuthorizeEntry(context.Background(), entry, signer, testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("AuthorizeEntry: %v", err)
	}
	tests := []struct {
		name      string
		signature xdr.ScVal
	}{
		{name: "opaque bytes", signature: scBytes([]byte("not an account signature"))},
		{name: "a map", signature: scMapVal()},
		{name: "a vector holding two maps", signature: scVec(scMapVal(), scMapVal())},
		{name: "a vector holding a symbol", signature: scVec(scSymbol("x"))},
		{name: "an integer", signature: scI64(1)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			candidate := signed
			candidateCredentials, err := addressCredentials(candidate.Credentials)
			if err != nil {
				t.Fatalf("addressCredentials: %v", err)
			}
			candidateCredentials.Signature = tt.signature

			report, err := VerifyEntry(candidate, network.TestNetworkPassphrase)
			if err != nil {
				t.Fatalf("VerifyEntry: %v", err)
			}
			if len(report.Nodes) != 1 {
				t.Fatalf("got %d nodes, want 1", len(report.Nodes))
			}
			if report.Nodes[0].Verdict != VerdictCannotCheck {
				t.Errorf("verdict = %q, want %q", report.Nodes[0].Verdict, VerdictCannotCheck)
			}
			if !strings.Contains(report.Nodes[0].Reason, "__check_auth") && !strings.Contains(report.Nodes[0].Reason, "cannot be checked offline") {
				t.Errorf("reason %q does not explain that only the account defines validity", report.Nodes[0].Reason)
			}
		})
	}
}

// TestVerifyEntryReportsUnsignedNode covers the empty-vector placeholder the
// simulation and the JS reference both use, and the Void placeholder CAP-71-01
// permits.
func TestVerifyEntryReportsUnsignedNode(t *testing.T) {
	tests := []struct {
		name      string
		signature xdr.ScVal
	}{
		{name: "void", signature: xdr.ScVal{Type: xdr.ScValTypeScvVoid}},
		{name: "empty vector", signature: scVec()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 5)
			credentials, err := addressCredentials(entry.Credentials)
			if err != nil {
				t.Fatalf("addressCredentials: %v", err)
			}
			credentials.Signature = tt.signature

			report, err := VerifyEntry(entry, network.TestNetworkPassphrase)
			if err != nil {
				t.Fatalf("VerifyEntry: %v", err)
			}
			if len(report.Nodes) != 1 || report.Nodes[0].Verdict != VerdictUnsigned {
				t.Fatalf("got %+v, want one unsigned node", report.Nodes)
			}
			if !report.HasUnsignedNodes() {
				t.Error("HasUnsignedNodes() = false for an unsigned node")
			}
			if report.Verified() {
				t.Error("Verified() = true for an unsigned node")
			}
		})
	}
}

// TestVerifyEntryCannotCheckAContractNode proves a node addressed to a C…
// contract is never verified, whatever its signature looks like.
func TestVerifyEntryCannotCheckAContractNode(t *testing.T) {
	contractAddress, err := ParseAddress(testContractAddress(t, "verify-contract-address"))
	if err != nil {
		t.Fatalf("ParseAddress: %v", err)
	}

	accountKey, err := rawEd25519Key(testKeypair(t, "verify-contract-node").Address())
	if err != nil {
		t.Fatalf("rawEd25519Key: %v", err)
	}
	// A correctly shaped signature, so only the contract-address rule can be
	// what produces the verdict.
	signature := scVec(accountSignature(accountKey, make([]byte, ed25519.SignatureSize)))

	credentials := xdr.SorobanAddressCredentials{
		Address:                   contractAddress,
		Nonce:                     11,
		SignatureExpirationLedger: 0,
		Signature:                 signature,
	}
	entry := xdr.SorobanAuthorizationEntry{
		Credentials:    xdr.SorobanCredentials{Type: xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, AddressV2: &credentials},
		RootInvocation: testInvocation(t),
	}

	report, err := VerifyEntry(entry, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("VerifyEntry: %v", err)
	}
	if len(report.Nodes) != 1 {
		t.Fatalf("got %d nodes, want 1", len(report.Nodes))
	}
	if report.Nodes[0].Verdict != VerdictCannotCheck {
		t.Errorf("verdict = %q (%s), want %q", report.Nodes[0].Verdict, report.Nodes[0].Reason, VerdictCannotCheck)
	}
	if !strings.Contains(report.Nodes[0].Reason, "__check_auth") {
		t.Errorf("reason %q does not name the contract as the authority", report.Nodes[0].Reason)
	}
}

// TestVerifyEntryCannotCheckAnUnsignedContractNode pins the precedence the
// contract-address rule has over the placeholder rule: a C… node is
// cannot_check whatever its signature, including the Void and empty-vector
// placeholders that would be "unsigned" on an account node. The docs list a
// contract node under cannot_check and a placeholder under unsigned; this is
// the case where both descriptions fit and the contract one wins, because a
// placeholder handed to __check_auth may itself be meaningful.
func TestVerifyEntryCannotCheckAnUnsignedContractNode(t *testing.T) {
	contractAddress, err := ParseAddress(testContractAddress(t, "verify-unsigned-contract-address"))
	if err != nil {
		t.Fatalf("ParseAddress: %v", err)
	}

	tests := []struct {
		name      string
		signature xdr.ScVal
	}{
		{name: "void", signature: xdr.ScVal{Type: xdr.ScValTypeScvVoid}},
		{name: "empty vector", signature: scVec()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			credentials := xdr.SorobanAddressCredentials{
				Address:                   contractAddress,
				Nonce:                     12,
				SignatureExpirationLedger: 0,
				Signature:                 tt.signature,
			}
			entry := xdr.SorobanAuthorizationEntry{
				Credentials:    xdr.SorobanCredentials{Type: xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, AddressV2: &credentials},
				RootInvocation: testInvocation(t),
			}

			report, err := VerifyEntry(entry, network.TestNetworkPassphrase)
			if err != nil {
				t.Fatalf("VerifyEntry: %v", err)
			}
			if len(report.Nodes) != 1 {
				t.Fatalf("got %d nodes, want 1", len(report.Nodes))
			}
			if report.Nodes[0].Verdict != VerdictCannotCheck {
				t.Errorf("verdict = %q (%s), want %q", report.Nodes[0].Verdict, report.Nodes[0].Reason, VerdictCannotCheck)
			}
			if report.HasUnsignedNodes() {
				t.Error("a contract node was reported unsigned; it must be cannot_check")
			}
		})
	}
}

// TestVerifyEntryNestedDelegateTree signs a top-level node plus a delegate that
// itself has a nested delegate, and checks that every node is reached.
func TestVerifyEntryNestedDelegateTree(t *testing.T) {
	helper := NewEd25519Signer(testKeypair(t, "verify-nested-helper"))
	// The top-level signer must own the entry's own address, because
	// AuthorizeEntry only writes onto a node whose address equals the target.
	top := NewEd25519Signer(testKeypair(t, "soroauth-preimage-signer"))
	nested := NewEd25519Signer(testKeypair(t, "verify-nested-inner"))

	unsigned := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 21)
	wrapped, err := WithDelegates(unsigned, testValidUntilLedger, []Delegate{{
		Address: helper.Address(),
		Nested:  []Delegate{{Address: nested.Address()}},
	}}, nil)
	if err != nil {
		t.Fatalf("WithDelegates: %v", err)
	}

	signed := wrapped
	for _, signer := range []Signer{top, helper, nested} {
		signed, err = AuthorizeEntry(context.Background(), signed, signer, testValidUntilLedger, network.TestNetworkPassphrase)
		if err != nil {
			t.Fatalf("AuthorizeEntry(%s): %v", signer.Address(), err)
		}
	}

	report, err := VerifyEntry(signed, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("VerifyEntry: %v", err)
	}
	// Top-level plus the outer delegate plus the nested delegate.
	if len(report.Nodes) != 3 {
		t.Fatalf("got %d nodes, want 3: %+v", len(report.Nodes), report.Nodes)
	}
	for i, node := range report.Nodes {
		if node.Verdict != VerdictVerified {
			t.Errorf("node %d (%s) verdict %q (%s), want %q", i, node.Address, node.Verdict, node.Reason, VerdictVerified)
		}
	}
	if !report.Verified() {
		t.Error("Verified() = false for a fully signed tree")
	}
}

// TestVerifyEntrySourceAccount covers the pass-through arm: there is nothing to
// check and the report says so.
func TestVerifyEntrySourceAccount(t *testing.T) {
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount, 3)

	report, err := VerifyEntry(entry, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("VerifyEntry: %v", err)
	}
	if report.CredentialType != CredentialTypeSourceAccount {
		t.Errorf("CredentialType = %q, want %q", report.CredentialType, CredentialTypeSourceAccount)
	}
	if len(report.Nodes) != 0 {
		t.Errorf("got %d nodes, want 0", len(report.Nodes))
	}
	if report.Note == "" {
		t.Error("no note explaining that the envelope covers the source-account arm")
	}
	if !report.Verified() {
		t.Error("Verified() = false; there is nothing in this arm that can fail")
	}
}

func TestVerifyEntryUnsupportedArm(t *testing.T) {
	entry := xdr.SorobanAuthorizationEntry{
		Credentials:    xdr.SorobanCredentials{Type: xdr.SorobanCredentialsType(99)},
		RootInvocation: testInvocation(t),
	}

	_, err := VerifyEntry(entry, network.TestNetworkPassphrase)
	if !errors.Is(err, ErrUnsupportedCredentials) {
		t.Fatalf("err = %v, want ErrUnsupportedCredentials", err)
	}
}

func TestVerifyEntryRejectsEmptyPassphrase(t *testing.T) {
	entry, _ := signedEntryFixture(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2)

	_, err := VerifyEntry(entry, "")
	if err == nil {
		t.Fatal("VerifyEntry accepted an empty network passphrase")
	}
}

// TestVerifyEntryDoesNotMutateInput holds VerifyEntry to the same guarantee
// every other entry-taking function gives: the caller's entry is never
// written to.
func TestVerifyEntryDoesNotMutateInput(t *testing.T) {
	entry, signer := signedEntryFixture(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates)
	signed, err := AuthorizeEntry(context.Background(), entry, signer, testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("AuthorizeEntry: %v", err)
	}

	before, err := signed.MarshalBinary()
	if err != nil {
		t.Fatalf("marshalling before: %v", err)
	}

	if _, err := VerifyEntry(signed, network.TestNetworkPassphrase); err != nil {
		t.Fatalf("VerifyEntry: %v", err)
	}

	after, err := signed.MarshalBinary()
	if err != nil {
		t.Fatalf("marshalling after: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Errorf("VerifyEntry mutated its input\n before %x\n  after %x", before, after)
	}
}

// scMapVal and scI64 are small ScVal constructors the custom-shape table needs;
// the accountSignature builder in signer.go covers the shape these are not.
func scMapVal() xdr.ScVal {
	entries := xdr.ScMap{{Key: scSymbol("not_a_signature"), Val: scBytes([]byte("x"))}}
	p := &entries
	return xdr.ScVal{Type: xdr.ScValTypeScvMap, Map: &p}
}

func scI64(v int64) xdr.ScVal {
	value := xdr.Int64(v)
	return xdr.ScVal{Type: xdr.ScValTypeScvI64, I64: &value}
}

// independentPayload rebuilds the payload exactly the way VerifyEntry does but
// standalone, so the fuzz target can re-verify a `verified` verdict rather than
// trusting the engine's own word for it. hasPayload is false for the
// source-account arm, which has no payload of its own.
func independentPayload(entry xdr.SorobanAuthorizationEntry) (payload [32]byte, hasPayload bool, err error) {
	if entry.Credentials.Type == xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount {
		return [32]byte{}, false, nil
	}
	credentials, err := addressCredentials(entry.Credentials)
	if err != nil {
		return [32]byte{}, false, err
	}
	preimage, err := Preimage(entry, uint32(credentials.SignatureExpirationLedger), network.TestNetworkPassphrase)
	if err != nil {
		return [32]byte{}, false, err
	}
	payload, err = Payload(preimage)
	if err != nil {
		return [32]byte{}, false, err
	}
	return payload, true, nil
}

// FuzzVerifyEntry feeds arbitrary entry bytes through VerifyEntry and checks the
// guarantees docs/verification-limits.md states, as invariants:
//
//   - It never reports verified for a signature crypto/ed25519 rejects. A
//     verified verdict is independently re-checked here, so a false verified —
//     the worst output this library can produce — cannot pass unnoticed.
//   - An invalid verdict corresponds to a readable signature ed25519 rejects,
//     and a cannot_check verdict on an account node to a signature the account
//     shape cannot read.
//   - A node addressed to a C… contract is always cannot_check, whatever its
//     signature value, and never verified.
//   - Malformed, truncated and wrong-type signature values produce a verdict
//     rather than a panic; a panic is a fuzz finding by construction.
//
// The golden vectors are the committed seeds (cmd/gencorpus); this target adds
// corrupted signature shapes on top, which are the inputs a decoder written to
// assume well-formed signatures would break on.
func FuzzVerifyEntry(f *testing.F) {
	// Seed with a realistic signed entry, then the corrupted variants. The
	// helpers take testing.TB, which *testing.F satisfies; a &testing.T{}
	// literal would panic on Helper/Fatalf rather than report a bad seed.
	entry := entryForArm(f, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)
	signer := NewEd25519Signer(testKeypair(f, "soroauth-preimage-signer"))
	if signed, err := AuthorizeEntry(context.Background(), entry, signer, testValidUntilLedger, network.TestNetworkPassphrase); err == nil {
		if raw, err := signed.MarshalBinary(); err == nil {
			f.Add(raw)
		}
		for _, corrupt := range corruptSignatureShapes(f, signed) {
			f.Add(corrupt)
		}
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var entry xdr.SorobanAuthorizationEntry
		if err := entry.UnmarshalBinary(data); err != nil {
			return
		}

		report, err := VerifyEntry(entry, network.TestNetworkPassphrase)
		if err != nil {
			// An unsupported credentials arm, or a body this engine refuses,
			// is a clean error and not a report. A refusal is safe.
			return
		}

		if entry.Credentials.Type == xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount {
			if len(report.Nodes) != 0 {
				t.Errorf("source-account entry reported %d nodes, want 0", len(report.Nodes))
			}
			return
		}

		nodes, err := credentialNodes(&entry)
		if err != nil {
			t.Fatalf("VerifyEntry returned a report but the credential nodes are unreadable: %v", err)
		}
		if len(report.Nodes) != len(nodes) {
			t.Fatalf("VerifyEntry reported %d nodes, credentialNodes found %d", len(report.Nodes), len(nodes))
		}

		payload, hasPayload, err := independentPayload(entry)
		if err != nil {
			t.Fatalf("VerifyEntry returned a report but the payload will not rebuild: %v", err)
		}
		if !hasPayload {
			t.Fatal("a non-source entry produced no payload")
		}

		for i, verdict := range report.Nodes {
			signature := *nodes[i].signature

			var address xdr.ScAddress
			if err := address.UnmarshalBinary(nodes[i].encoded); err != nil {
				t.Fatalf("node %d address will not decode: %v", i, err)
			}

			if address.Type != xdr.ScAddressTypeScAddressTypeAccount {
				if verdict.Verdict != VerdictCannotCheck {
					t.Errorf("contract node %d reported %q, want %q", i, verdict.Verdict, VerdictCannotCheck)
				}
				continue
			}

			switch verdict.Verdict {
			case VerdictVerified:
				publicKey, rawSignature, err := parseAccountSignature(signature)
				if err != nil {
					t.Fatalf("node %d reported verified but its shape is unreadable: %v", i, err)
				}
				if !ed25519.Verify(ed25519.PublicKey(publicKey), payload[:], rawSignature) {
					t.Errorf("node %d reported verified but crypto/ed25519 rejects the signature", i)
				}
			case VerdictInvalid:
				publicKey, rawSignature, err := parseAccountSignature(signature)
				if err != nil {
					t.Fatalf("node %d reported invalid but its shape is unreadable: %v", i, err)
				}
				if ed25519.Verify(ed25519.PublicKey(publicKey), payload[:], rawSignature) {
					t.Errorf("node %d reported invalid but crypto/ed25519 accepts the signature", i)
				}
			case VerdictUnsigned:
				if isSigned(signature) {
					t.Errorf("node %d reported unsigned but carries a signature", i)
				}
			case VerdictCannotCheck:
				if _, _, err := parseAccountSignature(signature); err == nil {
					t.Errorf("node %d reported cannot_check for a readable account signature", i)
				}
			default:
				t.Errorf("node %d reported an unknown verdict %q", i, verdict.Verdict)
			}
		}
	})
}

// corruptSignatureShapes returns a signed entry re-encoded with a range of
// malformed, truncated and wrong-type signature values, the inputs
// docs/verification-limits.md says must produce a verdict and never a panic.
func corruptSignatureShapes(t testing.TB, signed xdr.SorobanAuthorizationEntry) [][]byte {
	t.Helper()

	shapes := []xdr.ScVal{
		{Type: xdr.ScValTypeScvVoid},
		scVec(),
		scBytes([]byte("not the account shape")),
		scI64(7),
		scVec(scMapVal(), scMapVal()),
		scVec(scMapVal()),
		scVec(scSymbol("x")),
	}

	var out [][]byte
	for _, shape := range shapes {
		candidate, err := xdrcopyEntry(t, signed)
		if err != nil {
			continue
		}
		credentials, err := addressCredentials(candidate.Credentials)
		if err != nil {
			continue
		}
		credentials.Signature = shape
		if raw, err := candidate.MarshalBinary(); err == nil {
			out = append(out, raw)
		}
	}

	// A truncated classic-account signature: a 31-byte public key and a
	// 63-byte signature, which a length-check written with the wrong constant
	// would accept.
	publicKey := make([]byte, ed25519.PublicKeySize-1)
	rawSignature := make([]byte, ed25519.SignatureSize-1)
	truncated := scVec(accountSignature(publicKey, rawSignature))
	if candidate, err := xdrcopyEntry(t, signed); err == nil {
		if credentials, err := addressCredentials(candidate.Credentials); err == nil {
			credentials.Signature = truncated
			if raw, err := candidate.MarshalBinary(); err == nil {
				out = append(out, raw)
			}
		}
	}

	return out
}
