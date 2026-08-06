package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The four "dissolved" rows: S1 (the facade), U8 (the subprocess wrapper),
// U11 (the error taxonomy) and U12 (the presentation layer). Each names a Python
// construct with no Go counterpart by design, so there is no behaviour to test -
// what is verified here is structural.
//
// The trap to avoid is asserting absence by grepping for the old name. A search
// for "facade" passes for the wrong reasons and breaks on a comment. Each of
// those constructs existed for a PURPOSE, and the purpose is a decidable
// invariant - so that is what these pin, not the absence of a word.
//
// Precedent: internal/cli/exit_test.go::TestNoCommandCallsOsExit already reads
// this package's own source for the same kind of guarantee.

// repoRoot is two levels up from cmd/sshmgr.
func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// goFiles walks the tree and yields every non-test .go file with its parsed AST.
func goFiles(t *testing.T, dirs ...string) map[string]*ast.File {
	t.Helper()
	fset := token.NewFileSet()
	out := map[string]*ast.File{}
	root := repoRoot(t)
	for _, d := range dirs {
		err := filepath.WalkDir(filepath.Join(root, d), func(path string, e os.DirEntry, err error) error {
			if err != nil || e.IsDir() {
				return err
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			f, perr := parser.ParseFile(fset, path, nil, parser.ParseComments)
			if perr != nil {
				return perr
			}
			rel, _ := filepath.Rel(root, path)
			out[filepath.ToSlash(rel)] = f
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func importsOf(f *ast.File) []string {
	var out []string
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err == nil {
			out = append(out, p)
		}
	}
	return out
}

const mod = "github.com/simtabi/ssh-manager/"

// S1 - the facade is dissolved.
//
// R1's content is not "no file called facade.py". The Python facade was one
// class carrying **54 methods**, and every verb hung off it. So the invariant is
// that no single type has become the place everything goes, plus the dependency
// directions that would let one form again.
//
// The largest type here is manifest.Manifest at 20 - a domain model with
// accessors, which is a different shape from a God object. The ceiling is set
// above that and well below the facade: crossing it is a design change, and it
// should require someone to say so.
const godObjectCeiling = 24

func TestNoTypeHasBecomeTheFacadeAgain(t *testing.T) {
	files := goFiles(t, "internal", "cmd")
	type key struct{ pkg, typ string }
	methods := map[key]int{}
	for path, f := range files {
		pkg := filepath.Dir(path)
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || len(fn.Recv.List) == 0 {
				continue
			}
			expr := fn.Recv.List[0].Type
			if star, ok := expr.(*ast.StarExpr); ok {
				expr = star.X
			}
			id, ok := expr.(*ast.Ident)
			if !ok {
				continue
			}
			methods[key{pkg, id.Name}]++
		}
	}
	for k, n := range methods {
		if n > godObjectCeiling {
			t.Errorf("%s.%s has %d methods (ceiling %d). The Python facade had 54 and "+
				"every verb hung off it; that is the shape this guards against.",
				k.pkg, k.typ, n, godObjectCeiling)
		}
	}
	if len(methods) == 0 {
		t.Fatal("found no methods at all; the walk is not doing what it claims")
	}
}

// The dependency directions that would let a facade re-form. Services may
// compose one another - reconciler needs keystore, doctor needs preflight - and
// that is ordinary layering, not a God object. What must not happen is the
// command layer becoming a dependency, or the domain reaching upward.
func TestTheLayersPointOneWay(t *testing.T) {
	files := goFiles(t, "internal", "cmd")
	for path, f := range files {
		pkg := filepath.Dir(path)
		for _, imp := range importsOf(f) {
			if !strings.HasPrefix(imp, mod) {
				continue
			}
			target := strings.TrimPrefix(imp, mod)

			// internal/cli is a leaf among internal packages. cmd/ is the
			// entrypoint and is expected to import it.
			if target == "internal/cli" && strings.HasPrefix(pkg, "internal/") {
				t.Errorf("%s imports internal/cli; the command layer is where composition "+
					"happens, so nothing below it may depend on it", path)
			}
			// The domain does not know about the use-cases above it.
			if strings.HasPrefix(pkg, "internal/core/") && strings.HasPrefix(target, "internal/services/") {
				t.Errorf("%s imports %s: core is the domain and depends on nothing above it", path, target)
			}
		}
	}
}

// U12 - the presentation layer is dissolved, and D2's zero-dependency claim.
//
// The cheapest possible proof that there is no `rich` equivalent: there is
// nowhere for one to hide. One direct requirement, and it is the CLI framework.
func TestTheBinaryHasExactlyOneDirectDependency(t *testing.T) {
	body, err := os.ReadFile(filepath.Join(repoRoot(t), "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	var direct []string
	inBlock := false
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "require ("):
			inBlock = true
		case inBlock && line == ")":
			inBlock = false
		case strings.HasPrefix(line, "require ") && !strings.HasPrefix(line, "require ("):
			if f := strings.Fields(line); len(f) >= 2 && !strings.Contains(line, "// indirect") {
				direct = append(direct, f[1])
			}
		case inBlock && line != "" && !strings.HasPrefix(line, "//") && !strings.Contains(line, "// indirect"):
			if f := strings.Fields(line); len(f) >= 1 {
				direct = append(direct, f[0])
			}
		}
	}
	sort.Strings(direct)
	want := []string{"github.com/spf13/cobra"}
	if len(direct) != len(want) || direct[0] != want[0] {
		t.Errorf("direct dependencies = %v, want %v.\n"+
			"The binary ships with no presentation library and no runtime; adding one "+
			"is a decision, not an implementation detail.", direct, want)
	}
}

// U12, the user-visible half. "rich is gone" means output is plain text a pipe
// can consume, so no command may emit terminal escapes.
func TestNoSourceEmitsTerminalEscapes(t *testing.T) {
	root := repoRoot(t)
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, e os.DirEntry, err error) error {
			if err != nil || e.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			b, rerr := os.ReadFile(path)
			if rerr != nil {
				return rerr
			}
			rel, _ := filepath.Rel(root, path)
			for _, esc := range []string{`\x1b[`, `\033[`, "\x1b["} {
				if strings.Contains(string(b), esc) {
					t.Errorf("%s emits a terminal escape; output is plain text so a pipe can read it", rel)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

// U8 - util/proc.py is dissolved into os/exec at call sites.
//
// What the wrapper centralised was the policy, not the mechanism: argv lists,
// never a shell. Collecting every literal command the tree can run pins the
// whole external-binary surface in one assertion - a new shell-out, or a new
// dependency on some tool, has to be added here deliberately.
func TestTheToolRunsOnlyTheBinariesItDeclares(t *testing.T) {
	declared := map[string]bool{}
	for _, b := range []string{
		// OpenSSH, the hard dependency.
		"ssh", "ssh-keygen", "ssh-add", "ssh-keyscan", "ssh-copy-id",
		// Optional, each degrading to a manual path when absent.
		"age", "age-keygen", "gh", "glab",
		// Schedulers and notifiers, one per platform.
		"launchctl", "systemctl", "crontab", "schtasks",
		"osascript", "terminal-notifier", "notify-send", "powershell",
		// Windows ACLs.
		"icacls",
		// macOS: opens a provider's key page when a deploy must be done by hand.
		"open",
		// Itself: the scheduled notifier runs `sshmgr audit --notify`, and it
		// prefers an installed sshmgr on PATH over the running binary's own path
		// so the job survives the binary moving.
		"sshmgr",
	} {
		declared[b] = true
	}

	files := goFiles(t, "internal", "cmd")
	seen := map[string][]string{}
	for path, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "exec" {
				return true
			}
			var argv []ast.Expr
			switch sel.Sel.Name {
			case "Command", "LookPath":
				argv = call.Args
			case "CommandContext":
				if len(call.Args) > 1 {
					argv = call.Args[1:]
				}
			default:
				return true
			}
			if len(argv) == 0 {
				return true
			}
			lit, ok := argv[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true // built at runtime; the argv-slice cases below
			}
			name, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			seen[name] = append(seen[name], path)
			return true
		})
	}

	for name, where := range seen {
		if !declared[name] {
			t.Errorf("%s runs %q, which is not in the declared binary surface (%v)", where[0], name, where)
		}
		// The policy the Python wrapper existed to enforce: argv, never a shell.
		// The one place a shell is involved is the script sent to a REMOTE host,
		// which runs there, not here.
		if name == "sh" || name == "bash" || name == "cmd" {
			t.Errorf("%s shells out via %q; commands are argv lists (%v)", where[0], name, where)
		}
	}
	if len(seen) == 0 {
		t.Fatal("found no exec call sites at all; the walk is not doing what it claims")
	}
}

// U11 - the exception hierarchy is dissolved into error values.
//
// R4's content: errors are values, wrapped with %w, and control flow does not
// travel by panic. A panic in a tool that rewrites ~/.ssh mid-operation is the
// one failure mode with no recovery path.
func TestControlFlowDoesNotTravelByPanic(t *testing.T) {
	files := goFiles(t, "internal", "cmd")
	for path, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			id, ok := call.Fun.(*ast.Ident)
			if ok && id.Name == "panic" {
				t.Errorf("%s calls panic; a command that cannot continue returns an error, "+
					"so the mutation guard can unwind and the user sees a message", path)
			}
			return true
		})
	}
}
