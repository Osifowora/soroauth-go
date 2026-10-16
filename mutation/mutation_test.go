//go:build mutation

package mutation_test

import (
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/gtramontina/ooze"
	"github.com/gtramontina/ooze/viruses/comparison"
	"github.com/gtramontina/ooze/viruses/comparisoninvert"
	"github.com/gtramontina/ooze/viruses/integerincrement"
)

// targets are the signing-path files in scope. Keeping the mutant population to
// the preimage builder, the authorizer, the delegate tree and the diff keeps the
// signal high: mutating the whole repository drowns it.
var targets = []string{
	"preimage.go",
	"authorize.go",
	"delegates.go",
	"diff.go",
}

func TestMutation(t *testing.T) {
	ooze.Release(
		t,
		ooze.WithRepositoryRoot(".."),
		ooze.IgnoreSourceFiles(ignoredExcept(targets...)),
		ooze.WithTestCommand("go test -count=1 ."),
		ooze.Parallel(),
		ooze.WithViruses(
			comparison.New(),
			comparisoninvert.New(),
			integerincrement.New(),
		),
	)
}

// ignoredExcept returns a pattern matching every non-test Go file under the
// repository root except the named ones. Ooze has no allow-list, so the scope is
// expressed by ignoring everything else.
func ignoredExcept(keep ...string) string {
	wanted := make(map[string]bool, len(keep))
	for _, name := range keep {
		wanted[name] = true
	}

	var alternatives []string
	_ = filepath.WalkDir("..", func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		relative := filepath.ToSlash(strings.TrimPrefix(path, "../"))
		if wanted[relative] {
			return nil
		}
		alternatives = append(alternatives, "^"+regexp.QuoteMeta(relative)+"$")
		return nil
	})

	return strings.Join(alternatives, "|")
}
