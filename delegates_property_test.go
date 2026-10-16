package soroauth

import (
	"bytes"
	"errors"
	"math/rand"
	"reflect"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/prop"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// The property generators below cap generated depth well below
// MaxDecodeDepth (64). A tree past that ceiling is refused by WithDelegates for
// a different reason than the invariants under test, so generating one would
// mistake a deliberate refusal for a failure.
const (
	delegatePropMaxDepth = 4
	delegatePropMaxWidth = 3
)

// genDelegateAddress returns a valid G… or C… address, chosen at random.
func randomDelegateAddress(rng *rand.Rand) string {
	payload := make([]byte, 32)
	if _, err := rng.Read(payload); err != nil {
		panic(err)
	}
	version := strkey.VersionByteAccountID
	if rng.Intn(2) == 1 {
		version = strkey.VersionByteContract
	}
	address, err := strkey.Encode(version, payload)
	if err != nil {
		panic(err)
	}
	return address
}

// randomLevelAddresses builds one level's addresses with no repeats. Most
// addresses are derived from the previous one by nudging the last payload byte,
// so comparisons that are only exercised by near-neighbours — the ones a
// `<`/`<=` bug hides among — are common. The type is sometimes flipped mid-level
// so the account/contract discriminant ordering is exercised too.
func randomLevelAddresses(rng *rand.Rand, width int) []string {
	seen := make(map[string]bool, width)
	out := make([]string, 0, width)

	version := strkey.VersionByteAccountID
	if rng.Intn(2) == 1 {
		version = strkey.VersionByteContract
	}
	payload := make([]byte, 32)
	if _, err := rng.Read(payload); err != nil {
		panic(err)
	}

	for len(out) < width {
		if len(out) > 0 && rng.Intn(4) != 0 {
			// Adjacent by one to three bytes, which is where a comparison bug
			// lives: these addresses differ only at the very end of the XDR.
			next := make([]byte, 32)
			copy(next, payload)
			next[31] += byte(1 + rng.Intn(3))
			payload = next
		} else {
			if _, err := rng.Read(payload); err != nil {
				panic(err)
			}
			if rng.Intn(5) == 0 {
				if version == strkey.VersionByteAccountID {
					version = strkey.VersionByteContract
				} else {
					version = strkey.VersionByteAccountID
				}
			}
		}

		address, err := strkey.Encode(version, payload)
		if err != nil {
			panic(err)
		}
		if seen[address] {
			continue
		}
		seen[address] = true
		out = append(out, address)
	}
	return out
}

// randomTree builds a delegate tree with unique addresses within every level.
// parent carries the addresses seen on the way down, so a level can deliberately
// repeat an ancestor's address — legal under CAP-71-01, which forbids a repeat
// within one array and nothing else.
func randomTree(rng *rand.Rand, depth int, parent []string) []Delegate {
	if depth <= 0 {
		return nil
	}
	width := rng.Intn(delegatePropMaxWidth + 1)
	addresses := randomLevelAddresses(rng, width)

	// Repeating an ancestor at this level must stay a legal tree: the address
	// has to be absent from the level it is dropped into.
	if len(parent) > 0 && len(addresses) > 0 && rng.Intn(2) == 0 {
		candidate := parent[rng.Intn(len(parent))]
		conflicts := false
		for _, address := range addresses {
			if address == candidate {
				conflicts = true
				break
			}
		}
		if !conflicts {
			addresses[rng.Intn(len(addresses))] = candidate
		}
	}

	tree := make([]Delegate, 0, len(addresses))
	for _, address := range addresses {
		nested := []Delegate(nil)
		if depth > 1 {
			nested = randomTree(rng, depth-1, append(append([]string(nil), parent...), addresses...))
		}
		tree = append(tree, Delegate{Address: address, Nested: nested})
	}
	return tree
}

// randomDuplicateTree builds a tree with a repeated address within one level,
// at a randomly chosen depth. CAP-71-01 forbids exactly this, so WithDelegates
// must refuse the whole tree.
func randomDuplicateTree(rng *rand.Rand) []Delegate {
	depth := 1 + rng.Intn(delegatePropMaxDepth)

	first := randomDelegateAddress(rng)
	second := randomDelegateAddress(rng)
	for second == first {
		second = randomDelegateAddress(rng)
	}

	level := []Delegate{{Address: first}, {Address: second}}
	level[1].Address = level[0].Address // the deliberate repeat

	for i := 1; i < depth; i++ {
		parent := randomDelegateAddress(rng)
		level = []Delegate{{Address: parent, Nested: level}}
	}
	return level
}

// randomSharedTree builds a legal tree in which one address appears at the top
// level and again at depth ≥ 2. Repeating across levels is allowed; only a
// repeat within a single array is not.
func randomSharedTree(rng *rand.Rand) []Delegate {
	root := randomDelegateAddress(rng)

	depth := 2 + rng.Intn(delegatePropMaxDepth-1)
	tree := []Delegate{{Address: root}}
	cursor := tree
	for i := 1; i < depth; i++ {
		cursor[0].Nested = []Delegate{{Address: randomDelegateAddress(rng)}}
		cursor = cursor[0].Nested
	}
	cursor[0].Address = root
	return tree
}

// delegatePermutation is a tree paired with a reordering of every level, so the
// property can assert the wrapped result does not depend on input order.
type delegatePermutation struct {
	original []Delegate
	permuted []Delegate
}

func randomPermutationCase(rng *rand.Rand) delegatePermutation {
	original := randomTree(rng, delegatePropMaxDepth, nil)
	return delegatePermutation{original: original, permuted: permuteTree(rng, original)}
}

// permuteTree reshuffles every level independently and recurses. The order of
// delegates inside one level is the input order the cursor_soroban host must not
// depend on.
func permuteTree(rng *rand.Rand, tree []Delegate) []Delegate {
	out := make([]Delegate, 0, len(tree))
	for _, index := range rng.Perm(len(tree)) {
		node := tree[index]
		node.Nested = permuteTree(rng, node.Nested)
		out = append(out, node)
	}
	return out
}

// genTree wraps a constructor as a gopter generator, seeded from the property
// parameters so a failing case reproduces from the recorded seed.
func genTree(build func(*rand.Rand) []Delegate) gopter.Gen {
	return func(params *gopter.GenParameters) *gopter.GenResult {
		return gopter.NewGenResult(build(params.Rng), nil)
	}
}

func genPermutationCase() gopter.Gen {
	return func(params *gopter.GenParameters) *gopter.GenResult {
		return gopter.NewGenResult(randomPermutationCase(params.Rng), nil)
	}
}

// nodesAsDelegates turns a built delegate tree back into descriptors, preserving
// the stored order. Used to re-wrap an already-sorted tree and prove the sort is
// idempotent.
func nodesAsDelegates(nodes []xdr.SorobanDelegateSignature) []Delegate {
	out := make([]Delegate, 0, len(nodes))
	for _, node := range nodes {
		address, err := FormatAddress(node.Address)
		if err != nil {
			panic(err)
		}
		out = append(out, Delegate{Address: address, Nested: nodesAsDelegates(node.NestedDelegates)})
	}
	return out
}

// levelsStrictlyAscending reports whether every delegates array is strictly
// ascending by address XDR and free of duplicates, at every depth. This is the
// ordering CAP-71-01 requires and the host enforces.
func levelsStrictlyAscending(nodes []xdr.SorobanDelegateSignature) bool {
	var previous []byte
	for i := range nodes {
		current, err := addressBytes(nodes[i].Address)
		if err != nil {
			return false
		}
		if previous != nil && bytes.Compare(previous, current) >= 0 {
			return false
		}
		previous = current
		if !levelsStrictlyAscending(nodes[i].NestedDelegates) {
			return false
		}
	}
	return true
}

func propWithDelegatesSortsAndValidates(base xdr.SorobanAuthorizationEntry) gopter.Prop {
	return prop.ForAll(func(tree []Delegate) bool {
		wrapped, err := WithDelegates(base, testValidUntilLedger, tree, nil)
		if err != nil {
			return false
		}
		if wrapped.Credentials.Type != xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates {
			return false
		}
		if !levelsStrictlyAscending(wrapped.Credentials.AddressWithDelegates.Delegates) {
			return false
		}
		return ValidateDelegateOrder(wrapped) == nil
	}, genTree(func(rng *rand.Rand) []Delegate { return randomTree(rng, delegatePropMaxDepth, nil) }))
}

func propDuplicateWithinLevelRejected(base xdr.SorobanAuthorizationEntry) gopter.Prop {
	return prop.ForAll(func(tree []Delegate) bool {
		wrapped, err := WithDelegates(base, testValidUntilLedger, tree, nil)
		if err == nil {
			return false
		}
		var duplicate *DuplicateDelegateError
		return errors.As(err, &duplicate) && errors.Is(err, ErrDuplicateDelegate) &&
			reflect.DeepEqual(wrapped, xdr.SorobanAuthorizationEntry{})
	}, genTree(randomDuplicateTree))
}

func propSameAddressAcrossLevelsAccepted(base xdr.SorobanAuthorizationEntry) gopter.Prop {
	return prop.ForAll(func(tree []Delegate) bool {
		wrapped, err := WithDelegates(base, testValidUntilLedger, tree, nil)
		if err != nil {
			return false
		}
		return ValidateDelegateOrder(wrapped) == nil
	}, genTree(randomSharedTree))
}

func propOrderIndependentOfInput(base xdr.SorobanAuthorizationEntry) gopter.Prop {
	return prop.ForAll(func(c delegatePermutation) bool {
		first, err := WithDelegates(base, testValidUntilLedger, c.original, nil)
		if err != nil {
			return false
		}
		second, err := WithDelegates(base, testValidUntilLedger, c.permuted, nil)
		if err != nil {
			return false
		}
		left, err := first.MarshalBinary()
		if err != nil {
			return false
		}
		right, err := second.MarshalBinary()
		if err != nil {
			return false
		}
		return bytes.Equal(left, right)
	}, genPermutationCase())
}

func propSortingIdempotent(base xdr.SorobanAuthorizationEntry) gopter.Prop {
	return prop.ForAll(func(tree []Delegate) bool {
		once, err := WithDelegates(base, testValidUntilLedger, tree, nil)
		if err != nil {
			return false
		}
		// Re-wrap the tree the first call produced, in the order it produced.
		// Sorting is idempotent when the second pass is byte-identical.
		twice, err := WithDelegates(base, testValidUntilLedger,
			nodesAsDelegates(once.Credentials.AddressWithDelegates.Delegates), nil)
		if err != nil {
			return false
		}
		left, err := once.MarshalBinary()
		if err != nil {
			return false
		}
		right, err := twice.MarshalBinary()
		if err != nil {
			return false
		}
		return bytes.Equal(left, right)
	}, genTree(func(rng *rand.Rand) []Delegate { return randomTree(rng, delegatePropMaxDepth, nil) }))
}

// TestDelegateTreeProperties runs the delegate-tree invariants over a large
// random population. It is the search; the seeded variant below is the
// deterministic run CI executes.
func TestDelegateTreeProperties(t *testing.T) {
	base := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)

	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 1000
	parameters.MaxSize = 10

	properties := gopter.NewProperties(parameters)
	properties.Property("WithDelegates sorts and validates every level", propWithDelegatesSortsAndValidates(base))
	properties.Property("a duplicate within a level is rejected", propDuplicateWithinLevelRejected(base))
	properties.Property("the same address at different levels is accepted", propSameAddressAcrossLevelsAccepted(base))
	properties.Property("the result does not depend on input order", propOrderIndependentOfInput(base))
	properties.Property("sorting is idempotent", propSortingIdempotent(base))

	properties.TestingRun(t, gopter.ConsoleReporter(true))
}

// TestDelegateTreePropertiesDeterministic runs the deterministic subset with a
// fixed seed, matching the repository's property-test convention: CI runs this
// one, so a failure reproduces without the full search.
func TestDelegateTreePropertiesDeterministic(t *testing.T) {
	base := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)

	parameters := gopter.DefaultTestParametersWithSeed(0xDEADBEEF)
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 10

	properties := gopter.NewProperties(parameters)
	properties.Property("WithDelegates sorts and validates every level (deterministic)", propWithDelegatesSortsAndValidates(base))
	properties.Property("a duplicate within a level is rejected (deterministic)", propDuplicateWithinLevelRejected(base))
	properties.Property("the same address at different levels is accepted (deterministic)", propSameAddressAcrossLevelsAccepted(base))
	properties.Property("the result does not depend on input order (deterministic)", propOrderIndependentOfInput(base))
	properties.Property("sorting is idempotent (deterministic)", propSortingIdempotent(base))

	properties.TestingRun(t, gopter.ConsoleReporter(true))
}
