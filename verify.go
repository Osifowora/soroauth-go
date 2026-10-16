package soroauth

import (
	"context"
	"crypto/ed25519"
	"fmt"

	"github.com/stellar/go-stellar-sdk/xdr"
)

// VerifyVerdict is the per-node outcome of offline verification.
//
// There are four, not three, because a signature that is present, is in a
// shape this engine understands, and does not verify is a different thing to
// report than an unsigned node or a shape that cannot be checked. Collapsing a
// failed signature into "unsigned" would let a tampered entry read the same as
// an entry that was simply never signed.
type VerifyVerdict string

const (
	// VerdictVerified means the node carries a classic account signature (a
	// vector holding one {public_key, signature} map) and that signature
	// verifies over the payload the entry itself commits to.
	VerdictVerified VerifyVerdict = "verified"

	// VerdictUnsigned means the node carries no signature: its signature field
	// is ScvVoid or an empty ScvVec, the two placeholders simulation and the
	// JS reference use. Under CAP-71-01 a delegates entry may legitimately
	// leave its top-level node Void when every delegate authenticates, so an
	// unsigned node is reported, not failed, by this engine; whether it is
	// acceptable is the account's policy, which is not knowable offline.
	VerdictUnsigned VerifyVerdict = "unsigned"

	// VerdictInvalid means the node carries a classic account signature that
	// does not verify over the payload — the signature is the wrong bytes, or
	// the public key does not match it.
	VerdictInvalid VerifyVerdict = "invalid"

	// VerdictCannotCheck means the node's signature is not in the built-in
	// account shape, so this engine cannot decide it. That is the normal
	// outcome for a custom account (smart wallet) whose __check_auth defines
	// its own signature shape: only the contract can say whether the value is
	// valid. It is also the outcome for a node addressed to a C… contract, and
	// for any unrecognised shape. It is never reported as verified.
	VerdictCannotCheck VerifyVerdict = "cannot_check"
)

// NodeVerdict is the verification outcome for one credential node of an entry.
//
// One address can appear at several nodes of a delegates tree (CAP-71-01 binds
// the whole tree to the top-level address and every node signs the same
// payload), and each node is reported separately so a partially filled tree is
// visible rather than summarised away.
type NodeVerdict struct {
	// Address is the G… or C… strkey of the node this verdict is about.
	Address string `json:"address"`

	// Verdict is the outcome.
	Verdict VerifyVerdict `json:"verdict"`

	// Reason says why in plain language when the verdict is not VerdictVerified
	// or when it is verified with a caveat. It is empty for a plain pass.
	Reason string `json:"reason,omitempty"`
}

// VerificationReport is the result of VerifyEntry.
type VerificationReport struct {
	// CredentialType is the same stable string Inspect reports, so a caller can
	// switch on it: source_account, address, address_v2 or
	// address_with_delegates.
	CredentialType string `json:"credential_type"`

	// AddressBound is true for the arms whose payload binds the address into
	// the signed bytes (CAP-71-01): address_v2 and address_with_delegates.
	AddressBound bool `json:"address_bound"`

	// Address is the entry's address, for the three address arms.
	Address string `json:"address,omitempty"`

	// ValidUntilLedger is the expiration the payload was rebuilt with: the
	// value stored on the entry, never one supplied by the caller. See
	// VerifyEntry.
	ValidUntilLedger uint32 `json:"valid_until_ledger,omitempty"`

	// Nodes is one verdict per credential node, top-level first, then the
	// delegate tree depth-first. It is empty for the source-account arm.
	Nodes []NodeVerdict `json:"nodes,omitempty"`

	// Note carries a caveat about the whole report, such as the fact that a
	// source-account entry has nothing for this engine to check.
	Note string `json:"note,omitempty"`
}

// Verified reports whether every credential node in the report verified.
//
// It is true vacuously when there are no nodes — the source-account arm, which
// carries no payload of its own and is covered by the transaction envelope's
// signature. A node that is unsigned, invalid or cannot-check makes it false:
// verification fails closed, so only a node this engine actually checked and
// found correct counts as verified.
func (r VerificationReport) Verified() bool {
	for _, node := range r.Nodes {
		if node.Verdict != VerdictVerified {
			return false
		}
	}
	return true
}

// HasUnsignedNodes reports whether any node carries no signature at all.
//
// It is separate from Verified because under CAP-71-01 an unsigned top-level
// node is legitimate for an account that authenticates purely through
// delegates, so a caller can distinguish "unsigned" from "wrong".
func (r VerificationReport) HasUnsignedNodes() bool {
	for _, node := range r.Nodes {
		if node.Verdict == VerdictUnsigned {
			return true
		}
	}
	return false
}

// parseAccountSignature reads back the single {public_key, signature} map the
// host decodes as one AccountEd25519Signature.
//
// The host's struct is
//
//	pub(crate) struct AccountEd25519Signature {
//	    pub(crate) public_key: BytesN<32>,
//	    pub(crate) signature: BytesN<64>,
//	}
//
// (rs-soroban-env soroban-env-host/src/builtin_contracts/account_contract.rs:64).
// The keys are looked up by name rather than by position so a map written in
// either order reads back; the host requires key order, so only one order is
// ever valid on-chain, but this function is reading input the engine did not
// write and should not assume the host's own encoding.
//
// Anything that is not exactly one map carrying two byte strings of the right
// lengths is reported as unreadable, which the caller turns into
// VerdictCannotCheck rather than a verdict.
func parseAccountSignature(value xdr.ScVal) (publicKey, signature []byte, err error) {
	if value.Type != xdr.ScValTypeScvVec || value.Vec == nil || *value.Vec == nil {
		return nil, nil, fmt.Errorf("signature is %s, not the built-in account vector", value.Type)
	}

	entries := **value.Vec
	if len(entries) != 1 {
		return nil, nil, fmt.Errorf("signature vector holds %d entries, want exactly 1", len(entries))
	}

	element := entries[0]
	if element.Type != xdr.ScValTypeScvMap || element.Map == nil || *element.Map == nil {
		return nil, nil, fmt.Errorf("signature vector holds %s, not a map", element.Type)
	}

	for _, entry := range **element.Map {
		if entry.Key.Type != xdr.ScValTypeScvSymbol || entry.Key.Sym == nil {
			continue
		}
		if entry.Val.Type != xdr.ScValTypeScvBytes || entry.Val.Bytes == nil {
			return nil, nil, fmt.Errorf("signature field %q is %s, not bytes", *entry.Key.Sym, entry.Val.Type)
		}
		switch string(*entry.Key.Sym) {
		case "public_key":
			publicKey = *entry.Val.Bytes
		case "signature":
			signature = *entry.Val.Bytes
		}
	}

	if publicKey == nil || signature == nil {
		return nil, nil, fmt.Errorf("signature map is missing public_key or signature")
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, nil, fmt.Errorf("signature public key is %d bytes, want %d", len(publicKey), ed25519.PublicKeySize)
	}
	if len(signature) != ed25519.SignatureSize {
		return nil, nil, fmt.Errorf("signature is %d bytes, want %d", len(signature), ed25519.SignatureSize)
	}
	return publicKey, signature, nil
}

// contractAccountNote is the explanation attached to every node addressed to a
// C… contract, and the plainest statement of what offline verification cannot
// do.
const contractAccountNote = "the node addresses a C… contract; only the contract's __check_auth defines whether its signature is valid, so this cannot be checked offline"

// shapeNote is the explanation attached to a node whose signature is not the
// built-in classic account shape.
const shapeNote = "the signature is not the built-in {public_key, signature} account shape; only the account's own logic defines its validity, so this cannot be checked offline"

// VerifyEntry checks that an authorization entry's signatures verify against
// the payload the entry itself commits to, without submitting it.
//
// The payload is rebuilt from the entry — its credentials arm, nonce, address,
// invocation tree and, in particular, the SignatureExpirationLedger stored on
// the entry — through Preimage and Payload. The signature expiration is
// deliberately not a parameter: the question this answers is whether the
// entry, exactly as it stands, authorizes what it claims to. A caller that
// wants to know whether a *different* expiration would be accepted is asking
// about an entry that does not exist yet, and should build it first.
//
// Only classic account signatures — the built-in vector holding one
// {public_key, signature} map — can be decided offline. A custom account's
// __check_auth may accept any ScVal at all, and only the contract can say
// whether a given value is valid, so such a node is reported as
// VerdictCannotCheck and never as verified. The signature is checked against
// the public key it carries; whether that key is actually a signer of the
// account, and whether enough signers signed to meet the account's threshold,
// are questions about account state this engine cannot see offline and does
// not claim to answer.
//
// Every credential node in the entry is checked: the top-level node and, for
// the delegates arm, every delegate at every depth. A node with no signature
// is reported VerdictUnsigned rather than failed, because CAP-71-01 permits a
// Void top-level signature when only delegates authenticate; Verified reports
// it as not verified all the same, and a caller applies its own policy.
//
// An entry on the source-account arm has no payload of its own — the
// transaction envelope's signature covers it — and comes back with no nodes
// and a note saying so. An entry on an unknown credentials arm is refused with
// ErrUnsupportedCredentials rather than reported on.
//
// VerifyEntry does not modify entry.
func VerifyEntry(entry xdr.SorobanAuthorizationEntry, networkPassphrase string) (VerificationReport, error) {
	ctx := context.Background()
	return VerifyEntryContext(ctx, entry, networkPassphrase)
}

// VerifyEntryContext checks an authorization entry's signatures with a given context.
func VerifyEntryContext(ctx context.Context, entry xdr.SorobanAuthorizationEntry, networkPassphrase string) (VerificationReport, error) {
	if err := ctx.Err(); err != nil {
		return VerificationReport{}, fmt.Errorf("soroauth: verify entry: %w", err)
	}

	switch entry.Credentials.Type {
	case xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount:
		return VerificationReport{
			CredentialType: CredentialTypeSourceAccount,
			Note:           "source-account credentials carry no signature payload of their own; the transaction envelope's signature covers them, so there is nothing here to verify",
		}, nil

	case xdr.SorobanCredentialsTypeSorobanCredentialsAddress,
		xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2,
		xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates:
		// Handled below.

	default:
		return VerificationReport{}, fmt.Errorf("soroauth: verify entry: %w", ErrUnsupportedCredentials)
	}

	credentials, err := addressCredentials(entry.Credentials)
	if err != nil {
		return VerificationReport{}, fmt.Errorf("soroauth: verify entry: %w", err)
	}

	address, err := FormatAddress(credentials.Address)
	if err != nil {
		return VerificationReport{}, fmt.Errorf("soroauth: verify entry: %w", err)
	}

	expiration := uint32(credentials.SignatureExpirationLedger)
	preimage, err := Preimage(entry, expiration, networkPassphrase)
	if err != nil {
		return VerificationReport{}, fmt.Errorf("soroauth: verify entry for %s: %w", address, err)
	}
	payload, err := Payload(preimage)
	if err != nil {
		return VerificationReport{}, fmt.Errorf("soroauth: verify entry for %s: %w", address, err)
	}

	nodes, err := credentialNodes(&entry)
	if err != nil {
		return VerificationReport{}, fmt.Errorf("soroauth: verify entry: %w", err)
	}

	report := VerificationReport{
		CredentialType:   credentialTypeName(entry.Credentials.Type),
		AddressBound:     entry.Credentials.Type != xdr.SorobanCredentialsTypeSorobanCredentialsAddress,
		Address:          address,
		ValidUntilLedger: expiration,
		Nodes:            make([]NodeVerdict, 0, len(nodes)),
	}

	for _, node := range nodes {
		verdict, err := verifyNode(*node.signature, node.encoded, payload)
		if err != nil {
			return VerificationReport{}, fmt.Errorf("soroauth: verify entry: %w", err)
		}
		report.Nodes = append(report.Nodes, verdict)
	}

	return report, nil
}

// verifyNode decides one credential node's verdict.
//
// encoded is the XDR encoding of the node's address, which is how addresses
// are compared throughout this library and how the node's type is recovered.
// SignatureVerificationError represents an error during signature verification.
type SignatureVerificationError struct {
	Address string
	Reason  string
	Shape   SignatureShape
}

// Error returns the error message.
func (e *SignatureVerificationError) Error() string {
	return fmt.Sprintf("soroauth: verification failed for %s: %s (signature shape: %s - %s)", e.Address, e.Reason, e.Shape.Type, e.Shape.Description)
}

func verifyNode(signature xdr.ScVal, encoded []byte, payload [32]byte) (NodeVerdict, error) {
	var address xdr.ScAddress
	if err := address.UnmarshalBinary(encoded); err != nil {
		return NodeVerdict{}, fmt.Errorf("decoding credential node address: %w", err)
	}
	formatted, err := FormatAddress(address)
	if err != nil {
		return NodeVerdict{}, err
	}

	verdict := NodeVerdict{Address: formatted}

	// A node addressed to a contract is decided before the unsigned check: the
	// value it holds is whatever that contract's __check_auth expects, and a
	// placeholder may itself be meaningful to the contract. The engine cannot
	// say anything about it, so it is always cannot_check — never unsigned,
	// which would claim the node is simply unfilled, and never verified, which
	// is the one verdict this library must never produce wrongly.
	if address.Type != xdr.ScAddressTypeScAddressTypeAccount {
		verdict.Verdict = VerdictCannotCheck
		verdict.Reason = contractAccountNote
		return verdict, nil
	}

	if !isSigned(signature) {
		verdict.Verdict = VerdictUnsigned
		verdict.Reason = "the node carries no signature (Void or an empty vector)"
		return verdict, nil
	}

	publicKey, rawSignature, err := parseAccountSignature(signature)
	if err != nil {
		verdict.Verdict = VerdictCannotCheck
		verdict.Reason = fmt.Sprintf("%s (%v)", shapeNote, err)
		return verdict, nil
	}

	if !ed25519.Verify(ed25519.PublicKey(publicKey), payload[:], rawSignature) {
		verdict.Verdict = VerdictInvalid
		verdict.Reason = "the stored signature does not verify over the payload the entry commits to"
		return verdict, nil
	}

	verdict.Verdict = VerdictVerified
	return verdict, nil
}
