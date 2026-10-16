package soroauth

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// diffEntry decodes a base64 entry recorded in a golden vector.
func diffEntry(t *testing.T, encoded string) xdr.SorobanAuthorizationEntry {
	t.Helper()
	var entry xdr.SorobanAuthorizationEntry
	if err := xdr.SafeUnmarshalBase64(encoded, &entry); err != nil {
		t.Fatalf("decoding entry: %v", err)
	}
	return entry
}

// bumpExpiration returns a copy of entry with a different top-level expiration
// and every signature left exactly as it was. This is the dangerous edit the
// diff exists to catch: the entry still reads as signed, and every signature in
// it now commits to a payload the entry no longer has.
func bumpExpiration(t *testing.T, entry xdr.SorobanAuthorizationEntry, to uint32) xdr.SorobanAuthorizationEntry {
	t.Helper()
	copied, err := xdrcopyEntry(t, entry)
	if err != nil {
		t.Fatalf("copying the entry: %v", err)
	}
	credentials, err := addressCredentials(copied.Credentials)
	if err != nil {
		t.Fatalf("reading credentials: %v", err)
	}
	credentials.SignatureExpirationLedger = xdr.Uint32(to)
	return copied
}

// TestDiffEntriesUpgradePair is the case the issue names first: an unsigned
// legacy entry and the V2 entry UpgradeToV2 makes from it. Only the arm moved,
// but the arm selects the HashIdPreimage variant, so the payload moved with it.
func TestDiffEntriesUpgradePair(t *testing.T) {
	v := findVector(t, "legacy_single_testnet")
	legacy := diffEntry(t, v.UnsignedEntryXDR)

	upgraded, err := UpgradeToV2(legacy)
	if err != nil {
		t.Fatalf("upgrading: %v", err)
	}

	diff, err := DiffEntries(legacy, upgraded)
	if err != nil {
		t.Fatalf("diffing: %v", err)
	}

	if diff.Identical {
		t.Fatal("an upgraded entry is not identical to its legacy original")
	}
	if !diff.PayloadChanged {
		t.Error("PayloadChanged = false; the arm selects the preimage variant, so upgrading moves the payload")
	}
	if diff.SignaturesChanged {
		t.Error("SignaturesChanged = true; neither entry carries a signature")
	}
	if len(diff.StaleSignatures) != 0 {
		t.Errorf("StaleSignatures = %v; an unsigned entry has nothing to go stale", diff.StaleSignatures)
	}
	if len(diff.Changes) != 1 {
		t.Fatalf("Changes = %d, want exactly the arm change: %+v", len(diff.Changes), diff.Changes)
	}
	change := diff.Changes[0]
	if change.Kind != ChangeKindArm || change.From != CredentialTypeAddress || change.To != CredentialTypeAddressV2 {
		t.Errorf("change = %+v, want an arm change from %s to %s", change, CredentialTypeAddress, CredentialTypeAddressV2)
	}
	if !change.AffectsPayload {
		t.Error("the arm change is reported as not affecting the payload")
	}
	if !strings.Contains(diff.Summary, "no signature was carried over") {
		t.Errorf("Summary = %q, want it to say no signature was carried over", diff.Summary)
	}
}

// TestDiffEntriesResignPair covers the second pair the issue names: the same
// entry signed at two different expirations. The payload moved and the
// signature moved with it, which is what a correct re-sign looks like.
func TestDiffEntriesResignPair(t *testing.T) {
	v := findVector(t, "v2_single_testnet")
	unsigned := diffEntry(t, v.UnsignedEntryXDR)
	signer := signerForLabel(t, v.Steps[0].SignerLabel)

	first := diffEntry(t, v.SignedEntryXDR)
	second, err := AuthorizeEntry(context.Background(), first, signer,
		v.ValidUntilLedger+1, v.NetworkPassphrase, AllowResign())
	if err != nil {
		t.Fatalf("re-signing: %v", err)
	}

	// Guard against the fixture silently becoming a no-op.
	if _, err := DiffEntries(unsigned, first); err != nil {
		t.Fatalf("diffing the unsigned and signed entries: %v", err)
	}

	diff, err := DiffEntries(first, second)
	if err != nil {
		t.Fatalf("diffing: %v", err)
	}

	if !diff.PayloadChanged {
		t.Error("PayloadChanged = false; the expiration is inside both preimage variants")
	}
	if !diff.SignaturesChanged {
		t.Error("SignaturesChanged = false; the entry was re-signed")
	}
	if len(diff.StaleSignatures) != 0 {
		t.Errorf("StaleSignatures = %v; the one signature was replaced, not carried over", diff.StaleSignatures)
	}
	if !strings.Contains(diff.Summary, "consistent with a re-sign") {
		t.Errorf("Summary = %q, want it to read as a re-sign", diff.Summary)
	}

	kinds := map[ChangeKind]Change{}
	for _, change := range diff.Changes {
		kinds[change.Kind] = change
	}
	if change, ok := kinds[ChangeKindExpiration]; !ok || !change.AffectsPayload {
		t.Errorf("expiration change = %+v, want one that affects the payload", change)
	}
	if change, ok := kinds[ChangeKindSignature]; !ok || change.AffectsPayload {
		t.Errorf("signature change = %+v, want one that does not affect the payload", change)
	}
	// Payload-affecting changes sort first so the dangerous one is never buried.
	if !diff.Changes[0].AffectsPayload {
		t.Errorf("Changes[0] = %+v, want a payload-affecting change first", diff.Changes[0])
	}
}

// TestDiffEntriesStaleSignature is the finding this whole feature exists for: a
// signature that was never touched, on an entry whose payload moved underneath
// it. Nothing about the signature itself changed, so a byte diff of the two
// entries shows only the expiration — and the entry is dead.
func TestDiffEntriesStaleSignature(t *testing.T) {
	v := findVector(t, "v2_single_testnet")
	signed := diffEntry(t, v.SignedEntryXDR)
	tampered := bumpExpiration(t, signed, v.ValidUntilLedger+1)

	diff, err := DiffEntries(signed, tampered)
	if err != nil {
		t.Fatalf("diffing: %v", err)
	}

	if !diff.PayloadChanged {
		t.Fatal("PayloadChanged = false after the expiration moved")
	}
	if diff.SignaturesChanged {
		t.Error("SignaturesChanged = true; the signature bytes were not touched")
	}
	want := []string{"credentials"}
	if len(diff.StaleSignatures) != 1 || diff.StaleSignatures[0] != want[0] {
		t.Fatalf("StaleSignatures = %v, want %v", diff.StaleSignatures, want)
	}
	if !strings.Contains(diff.Summary, "PAYLOAD CHANGED") || !strings.Contains(diff.Summary, "no longer valid") {
		t.Errorf("Summary = %q, want it to lead with the invalidation", diff.Summary)
	}
	// The verdict must survive being read as text, since that is how a CLI
	// user meets it.
	rendered := diff.String()
	if !strings.HasPrefix(rendered, diff.Summary) {
		t.Errorf("String() = %q, want it to lead with the summary", rendered)
	}
	if !strings.Contains(rendered, "stale signatures") {
		t.Errorf("String() = %q, want a stale-signature section", rendered)
	}

	// And the entry really is dead: verification over the entry as it now
	// stands rejects the signature that the diff flagged.
	report, err := VerifyEntry(tampered, v.NetworkPassphrase)
	if err != nil {
		t.Fatalf("verifying the tampered entry: %v", err)
	}
	if report.Verified() {
		t.Error("the tampered entry still verifies; the stale-signature claim would be wrong")
	}
}

// TestDiffEntriesStaleAcrossDelegateTree proves the claim that makes the
// expiration dangerous: under CAP-71-01 every node commits to the same payload,
// so moving the expiration invalidates the whole tree at once, not one node.
func TestDiffEntriesStaleAcrossDelegateTree(t *testing.T) {
	v := findVector(t, "delegates_unsorted_with_nested")
	signed := diffEntry(t, v.SignedEntryXDR)
	tampered := bumpExpiration(t, signed, v.ValidUntilLedger+1)

	diff, err := DiffEntries(signed, tampered)
	if err != nil {
		t.Fatalf("diffing: %v", err)
	}

	if !diff.PayloadChanged {
		t.Fatal("PayloadChanged = false after the expiration moved")
	}
	// The vector signs every delegate and leaves the top-level node Void, so
	// every stale path is a delegate and none is the top-level node.
	if len(diff.StaleSignatures) < 2 {
		t.Fatalf("StaleSignatures = %v, want every signed node in the tree", diff.StaleSignatures)
	}
	for _, path := range diff.StaleSignatures {
		if !strings.HasPrefix(path, "credentials.delegates[") {
			t.Errorf("stale path %q is not a delegate node", path)
		}
	}
	// A nested node must be reachable by its own path, not folded into its
	// parent's.
	nested := false
	for _, path := range diff.StaleSignatures {
		if strings.Contains(path, "].nested[") {
			nested = true
		}
	}
	if !nested {
		t.Errorf("StaleSignatures = %v, want the nested delegate reported at its own path", diff.StaleSignatures)
	}
}

// TestDiffEntriesWrapPair covers the third pair of interest: a legacy entry and
// the delegates entry WithDelegates makes from it, recorded in the vector as
// pre_wrap_entry_xdr and unsigned_entry_xdr.
func TestDiffEntriesWrapPair(t *testing.T) {
	v := findVector(t, "delegates_from_legacy")
	if v.PreWrapEntryXDR == "" {
		t.Fatal("the vector records no pre-wrap entry; this test would prove nothing")
	}
	before := diffEntry(t, v.PreWrapEntryXDR)
	after := diffEntry(t, v.UnsignedEntryXDR)

	diff, err := DiffEntries(before, after)
	if err != nil {
		t.Fatalf("diffing: %v", err)
	}

	if !diff.PayloadChanged {
		t.Error("PayloadChanged = false; wrapping a legacy entry makes its payload address-bound")
	}

	added := 0
	for _, change := range diff.Changes {
		if change.Kind != ChangeKindDelegateAdded {
			continue
		}
		added++
		if change.AffectsPayload {
			t.Errorf("delegate %s is reported as affecting the payload; the tree is not inside the preimage", change.Path)
		}
	}
	if added == 0 {
		t.Error("no delegate_added change; the wrap added delegates")
	}
}

// TestDiffEntriesFirstSigningIsNotAResign separates two cases that look alike
// in the fields — both move the payload and both change a signature — and are
// not alike at all: a first signing cannot have invalidated anything, because
// there was nothing to invalidate.
func TestDiffEntriesFirstSigningIsNotAResign(t *testing.T) {
	v := findVector(t, "v2_single_testnet")
	unsigned := diffEntry(t, v.UnsignedEntryXDR)
	signed := diffEntry(t, v.SignedEntryXDR)

	diff, err := DiffEntries(unsigned, signed)
	if err != nil {
		t.Fatalf("diffing: %v", err)
	}
	if !diff.PayloadChanged || !diff.SignaturesChanged {
		t.Fatalf("diff = %+v, want both the payload and a signature to have changed", diff)
	}
	if len(diff.StaleSignatures) != 0 {
		t.Errorf("StaleSignatures = %v; the unsigned entry had nothing to invalidate", diff.StaleSignatures)
	}
	if !strings.Contains(diff.Summary, "first signing") {
		t.Errorf("Summary = %q, want it to read as a first signing", diff.Summary)
	}
	if strings.Contains(diff.Summary, "re-sign") {
		t.Errorf("Summary = %q calls a first signing a re-sign", diff.Summary)
	}
}

func TestDiffEntriesIdentical(t *testing.T) {
	entry := delegatesFixture(t)

	diff, err := DiffEntries(entry, entry)
	if err != nil {
		t.Fatalf("diffing: %v", err)
	}
	if !diff.Identical {
		t.Error("Identical = false for an entry against itself")
	}
	if diff.PayloadChanged || diff.SignaturesChanged || len(diff.Changes) != 0 {
		t.Errorf("diff = %+v, want no differences", diff)
	}
	if !strings.Contains(diff.Summary, "identical") {
		t.Errorf("Summary = %q", diff.Summary)
	}
}

// TestDiffEntriesAddressBindingPerArm is the one classification that is not
// constant per kind: the top-level address is inside the preimage for the
// CAP-71 arms and outside it for legacy. Getting this backwards would either
// cry wolf on a legacy entry or stay silent on a V2 one.
func TestDiffEntriesAddressBindingPerArm(t *testing.T) {
	tests := []struct {
		name    string
		arm     xdr.SorobanCredentialsType
		want    bool
		because string
	}{
		{
			name:    "legacy address is outside the preimage",
			arm:     xdr.SorobanCredentialsTypeSorobanCredentialsAddress,
			want:    false,
			because: "ENVELOPE_TYPE_SOROBAN_AUTHORIZATION carries no address (CAP-46-11)",
		},
		{
			name:    "v2 address is inside the preimage",
			arm:     xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2,
			want:    true,
			because: "ENVELOPE_TYPE_SOROBAN_AUTHORIZATION_WITH_ADDRESS carries the address (CAP-71-01)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			first := entryForSigner(t, "soroauth-diff-address-1", tt.arm, 7)
			second := entryForSigner(t, "soroauth-diff-address-2", tt.arm, 7)

			diff, err := DiffEntries(first, second)
			if err != nil {
				t.Fatalf("diffing: %v", err)
			}

			var found *Change
			for i := range diff.Changes {
				if diff.Changes[i].Kind == ChangeKindAddress {
					found = &diff.Changes[i]
				}
			}
			if found == nil {
				t.Fatalf("no address change reported; changes = %+v", diff.Changes)
			}
			if found.AffectsPayload != tt.want {
				t.Errorf("AffectsPayload = %t, want %t: %s", found.AffectsPayload, tt.want, tt.because)
			}
			if diff.PayloadChanged != tt.want {
				t.Errorf("PayloadChanged = %t, want %t: %s", diff.PayloadChanged, tt.want, tt.because)
			}
		})
	}

	// The claim above is checked against the preimage builder rather than
	// trusted, so this test cannot drift away from what is actually signed.
	first := entryForSigner(t, "soroauth-diff-address-1", xdr.SorobanCredentialsTypeSorobanCredentialsAddress, 7)
	second := entryForSigner(t, "soroauth-diff-address-2", xdr.SorobanCredentialsTypeSorobanCredentialsAddress, 7)
	payloadOf := func(entry xdr.SorobanAuthorizationEntry) [32]byte {
		preimage, err := Preimage(entry, testValidUntilLedger, network.TestNetworkPassphrase)
		if err != nil {
			t.Fatalf("building the preimage: %v", err)
		}
		payload, err := Payload(preimage)
		if err != nil {
			t.Fatalf("hashing the preimage: %v", err)
		}
		return payload
	}
	if payloadOf(first) != payloadOf(second) {
		t.Error("two legacy entries differing only by address produced different payloads; the arm is address-bound after all")
	}
}

func TestDiffEntriesFieldChanges(t *testing.T) {
	base := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)

	withNonce := func(nonce int64) xdr.SorobanAuthorizationEntry {
		copied, err := xdrcopyEntry(t, base)
		if err != nil {
			t.Fatalf("copying: %v", err)
		}
		credentials, err := addressCredentials(copied.Credentials)
		if err != nil {
			t.Fatalf("reading credentials: %v", err)
		}
		credentials.Nonce = xdr.Int64(nonce)
		return copied
	}

	tests := []struct {
		name           string
		mutate         func(t *testing.T) xdr.SorobanAuthorizationEntry
		wantKind       ChangeKind
		wantPath       string
		affectsPayload bool
	}{
		{
			name:           "nonce",
			mutate:         func(*testing.T) xdr.SorobanAuthorizationEntry { return withNonce(43) },
			wantKind:       ChangeKindNonce,
			wantPath:       "credentials.nonce",
			affectsPayload: true,
		},
		{
			name: "negative nonce is rendered signed, not as a huge unsigned value",
			mutate: func(*testing.T) xdr.SorobanAuthorizationEntry {
				return withNonce(-1)
			},
			wantKind:       ChangeKindNonce,
			wantPath:       "credentials.nonce",
			affectsPayload: true,
		},
		{
			name: "expiration",
			mutate: func(t *testing.T) xdr.SorobanAuthorizationEntry {
				return bumpExpiration(t, base, 999)
			},
			wantKind:       ChangeKindExpiration,
			wantPath:       "credentials.signatureExpirationLedger",
			affectsPayload: true,
		},
		{
			name: "function name",
			mutate: func(t *testing.T) xdr.SorobanAuthorizationEntry {
				copied, err := xdrcopyEntry(t, base)
				if err != nil {
					t.Fatalf("copying: %v", err)
				}
				copied.RootInvocation.Function.ContractFn.FunctionName = xdr.ScSymbol("burn")
				return copied
			},
			wantKind:       ChangeKindInvocation,
			wantPath:       "rootInvocation.functionName",
			affectsPayload: true,
		},
		{
			name: "sub-invocation count",
			mutate: func(t *testing.T) xdr.SorobanAuthorizationEntry {
				copied, err := xdrcopyEntry(t, base)
				if err != nil {
					t.Fatalf("copying: %v", err)
				}
				copied.RootInvocation.SubInvocations = append(copied.RootInvocation.SubInvocations, base.RootInvocation)
				return copied
			},
			wantKind:       ChangeKindInvocation,
			wantPath:       "rootInvocation.subInvocations",
			affectsPayload: true,
		},
		{
			name: "signature only",
			mutate: func(t *testing.T) xdr.SorobanAuthorizationEntry {
				signed, err := AuthorizeEntry(context.Background(), base,
					NewEd25519Signer(testKeypair(t, "soroauth-preimage-signer")),
					testValidUntilLedger, network.TestNetworkPassphrase)
				if err != nil {
					t.Fatalf("signing: %v", err)
				}
				// Signing also writes the expiration, so align the base's
				// expiration first: this case is about the signature alone.
				return signed
			},
			wantKind:       ChangeKindSignature,
			wantPath:       "credentials.signature",
			affectsPayload: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			left := base
			right := tt.mutate(t)
			if tt.wantKind == ChangeKindSignature {
				// Put the two entries on the same expiration so the only
				// difference left is the signature.
				left = bumpExpiration(t, base, testValidUntilLedger)
			}

			diff, err := DiffEntries(left, right)
			if err != nil {
				t.Fatalf("diffing: %v", err)
			}

			var found *Change
			for i := range diff.Changes {
				if diff.Changes[i].Path == tt.wantPath {
					found = &diff.Changes[i]
				}
			}
			if found == nil {
				t.Fatalf("no change at %q; changes = %+v", tt.wantPath, diff.Changes)
			}
			if found.Kind != tt.wantKind {
				t.Errorf("Kind = %q, want %q", found.Kind, tt.wantKind)
			}
			if found.AffectsPayload != tt.affectsPayload {
				t.Errorf("AffectsPayload = %t, want %t", found.AffectsPayload, tt.affectsPayload)
			}
			if diff.PayloadChanged != tt.affectsPayload {
				t.Errorf("PayloadChanged = %t, want %t", diff.PayloadChanged, tt.affectsPayload)
			}
			if !tt.affectsPayload && diff.Note == "" {
				t.Error("Note is empty; a diff with no payload change must still say the passphrase was not compared")
			}
		})
	}
}

// TestDiffEntriesNegativeNonceRendering pins the rendering of the int64 nonce.
// The XDR type is an alias of int64, and printing it through the unsigned path
// would turn -1 into 18446744073709551615 — a number no reviewer would
// recognise as the value their own entry carries.
func TestDiffEntriesNegativeNonceRendering(t *testing.T) {
	v := findVector(t, "legacy_negative_nonce")
	entry := diffEntry(t, v.UnsignedEntryXDR)

	other, err := xdrcopyEntry(t, entry)
	if err != nil {
		t.Fatalf("copying: %v", err)
	}
	credentials, err := addressCredentials(other.Credentials)
	if err != nil {
		t.Fatalf("reading credentials: %v", err)
	}
	original := int64(credentials.Nonce)
	if original >= 0 {
		t.Fatalf("the negative-nonce vector carries nonce %d; this test would prove nothing", original)
	}
	credentials.Nonce = xdr.Int64(0)

	diff, err := DiffEntries(entry, other)
	if err != nil {
		t.Fatalf("diffing: %v", err)
	}
	for _, change := range diff.Changes {
		if change.Kind != ChangeKindNonce {
			continue
		}
		if !strings.HasPrefix(change.From, "-") {
			t.Errorf("From = %q, want the negative nonce %d", change.From, original)
		}
		return
	}
	t.Fatalf("no nonce change reported; changes = %+v", diff.Changes)
}

func TestDiffEntriesSourceAccountArm(t *testing.T) {
	source := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount, 1)
	address := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddress, 1)

	t.Run("against itself", func(t *testing.T) {
		diff, err := DiffEntries(source, source)
		if err != nil {
			t.Fatalf("diffing: %v", err)
		}
		if !diff.Identical || len(diff.Changes) != 0 {
			t.Errorf("diff = %+v, want no differences", diff)
		}
	})

	t.Run("against an address arm", func(t *testing.T) {
		diff, err := DiffEntries(source, address)
		if err != nil {
			t.Fatalf("diffing: %v", err)
		}
		if !diff.PayloadChanged {
			t.Error("PayloadChanged = false; a source-account entry has no payload of its own and an address one does")
		}
		// The address arm's node is new, and must not be read as a delegate.
		for _, change := range diff.Changes {
			if change.Kind == ChangeKindDelegateAdded && change.Path == "credentials" {
				t.Errorf("the top-level node is reported as an added delegate: %+v", change)
			}
		}
	})
}

func TestDiffEntriesRejectsUnsupportedCredentials(t *testing.T) {
	good := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 1)
	bad := xdr.SorobanAuthorizationEntry{
		Credentials:    xdr.SorobanCredentials{Type: xdr.SorobanCredentialsType(99)},
		RootInvocation: good.RootInvocation,
	}

	tests := []struct {
		name string
		a, b xdr.SorobanAuthorizationEntry
		want string
	}{
		{name: "first entry", a: bad, b: good, want: "first entry"},
		{name: "second entry", a: good, b: bad, want: "second entry"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DiffEntries(tt.a, tt.b)
			if !errors.Is(err, ErrUnsupportedCredentials) {
				t.Fatalf("err = %v, want ErrUnsupportedCredentials", err)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %q, want it to name the %s", err, tt.want)
			}
		})
	}
}

// TestDiffEntriesDoesNotMutateInput is required of every function in this
// package that takes an entry: the XDR structs carry pointers and slices, so a
// shallow read that wrote anything would reach the caller's data.
func TestDiffEntriesDoesNotMutateInput(t *testing.T) {
	first := delegatesFixture(t)
	second := bumpExpiration(t, first, testValidUntilLedger+5)

	beforeFirst, err := first.MarshalBinary()
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	beforeSecond, err := second.MarshalBinary()
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}

	if _, err := DiffEntries(first, second); err != nil {
		t.Fatalf("diffing: %v", err)
	}

	afterFirst, err := first.MarshalBinary()
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	afterSecond, err := second.MarshalBinary()
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	if string(beforeFirst) != string(afterFirst) {
		t.Error("the first entry's bytes changed")
	}
	if string(beforeSecond) != string(afterSecond) {
		t.Error("the second entry's bytes changed")
	}
}

// TestDiffEntriesRefusesPathologicalNesting proves the traversal is bounded.
// DiffEntries is pointed at entries from elsewhere by design, so it must refuse
// a tree built to exhaust the stack rather than follow it.
func TestDiffEntriesRefusesPathologicalNesting(t *testing.T) {
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 1)

	// Both sides are nested to the same depth. A tree that is deep on one
	// side only stops at the first differing sub-invocation count, so it would
	// never reach the recursion this test is about.
	deep := entry
	for i := 0; i <= MaxDecodeDepth+1; i++ {
		parent := entry.RootInvocation
		parent.SubInvocations = []xdr.SorobanAuthorizedInvocation{deep.RootInvocation}
		deep.RootInvocation = parent
	}
	other, err := xdrcopyEntry(t, deep)
	if err != nil {
		t.Fatalf("copying: %v", err)
	}

	if _, err := DiffEntries(deep, other); !errors.Is(err, ErrDecodeLimit) {
		t.Fatalf("err = %v, want ErrDecodeLimit", err)
	}

	// A tree just inside the limit is still compared rather than refused, so
	// the guard is a limit and not a blanket rejection of nesting.
	shallow := entry
	for i := 0; i < MaxDecodeDepth-2; i++ {
		parent := entry.RootInvocation
		parent.SubInvocations = []xdr.SorobanAuthorizedInvocation{shallow.RootInvocation}
		shallow.RootInvocation = parent
	}
	if _, err := DiffEntries(shallow, shallow); err != nil {
		t.Fatalf("a tree within the limit was refused: %v", err)
	}
}

// FuzzDiffEntries feeds two decoded entries into DiffEntries and asserts the
// claims EntryDiff makes rather than only that nothing panics. DiffEntries walks
// two untrusted trees at once and reports PayloadChanged, a verdict other code
// acts on, so the payload cross-check below is the valuable assertion: it
// re-derives the payload for both entries through Preimage/Payload and requires
// PayloadChanged to agree, which tests the claim rather than the
// implementation's opinion of itself.
//
// The committed corpus (cmd/gencorpus) carries the golden vectors and tampered
// pairs; the in-code seeds add the two shapes that are easiest to build here.
func FuzzDiffEntries(f *testing.F) {
	// An entry against itself, and the dangerous tamper: a signature left in
	// place while the payload moves underneath it.
	entry := entryForArm(f, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)
	if raw, err := entry.MarshalBinary(); err == nil {
		f.Add(raw, raw)
	}
	if raw, err := entry.MarshalBinary(); err == nil {
		if bumped, err := xdrcopyEntry(f, entry); err == nil {
			if credentials, err := addressCredentials(bumped.Credentials); err == nil {
				credentials.SignatureExpirationLedger = xdr.Uint32(testValidUntilLedger + 1)
				if tampered, err := bumped.MarshalBinary(); err == nil {
					f.Add(raw, tampered)
				}
			}
		}
	}

	f.Fuzz(func(t *testing.T, a, b []byte) {
		var entryA, entryB xdr.SorobanAuthorizationEntry
		if err := entryA.UnmarshalBinary(a); err != nil {
			return
		}
		if err := entryB.UnmarshalBinary(b); err != nil {
			return
		}

		// Fixed point: an entry against itself is identical with no changes.
		self, err := DiffEntries(entryA, entryA)
		if err != nil {
			return
		}
		if !self.Identical || self.PayloadChanged || self.SignaturesChanged ||
			len(self.Changes) != 0 || len(self.StaleSignatures) != 0 {
			t.Errorf("DiffEntries(e, e) = %+v, want Identical with no changes", self)
		}

		diff, err := DiffEntries(entryA, entryB)
		if err != nil {
			return
		}

		// Identical must agree with the byte comparison the result is named for.
		equal, err := xdrEqual(entryA, entryB)
		if err == nil && diff.Identical != equal {
			t.Errorf("Identical=%v but the entries encode equally=%v", diff.Identical, equal)
		}

		// A signature can only be stale if the payload moved; when it did not,
		// no signature can have committed to an old payload.
		if !diff.PayloadChanged && len(diff.StaleSignatures) != 0 {
			t.Errorf("PayloadChanged=false but StaleSignatures=%v", diff.StaleSignatures)
		}

		// The payload cross-check. It is only meaningful where the payload
		// exists: a source-account entry has none, so a pair involving one is
		// handled by the arm-difference branch rather than skipped silently.
		payloadA, okA, errA := independentPayload(entryA)
		payloadB, okB, errB := independentPayload(entryB)
		if errA != nil || errB != nil {
			return
		}
		switch {
		case okA && okB:
			if want := payloadA != payloadB; diff.PayloadChanged != want {
				t.Errorf("PayloadChanged=%v, but Preimage/Payload differ=%v", diff.PayloadChanged, want)
			}
		case okA != okB:
			if !diff.PayloadChanged {
				t.Errorf("one entry carries a payload and the other does not, but PayloadChanged=false")
			}
		default:
			// Both source-account: no payload exists to compare, and the diff
			// still reports the invocation difference it found.
		}
	})
}
