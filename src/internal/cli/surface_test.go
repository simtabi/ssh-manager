package cli

import (
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// The command surface, checked against the implementation it was ported from.
//
// Transcribed from the v1 CLI, which declared every flag inline. This is the "same flags" half of the parity
// definition the matrix header uses, and it is the thing most at risk in a CLI
// port: a verb quietly renamed, a flag dropped in translation, a shorthand that
// silently changed meaning. None of that shows up in a service-level test.
//
// The table is checked in BOTH directions. A v1 flag that is missing fails;
// a Go verb or flag with no v1 counterpart fails too, unless it is listed in
// `goOnly` with the deviation that authorises it. So the surface cannot widen
// without someone writing down why.

// v1Surface is verb -> the long flags v1 declared on it. Subcommands are
// spelled "parent child". Verbs with no flags map to an empty slice.
var v1Surface = map[string][]string{
	"version":   {},
	"tui":       {},
	"recover":   {},
	"doctor":    {"fix", "json"},
	"init":      {"force", "backup"},
	"migrate":   {"force"},
	"import":    {"dry-run", "force"},
	"reconcile": {"dry-run", "passphrase", "no-pin"},
	"diff":      {},
	"keygen":    {"passphrase", "force", "no-pin"},
	"deploy":    {},
	"list":      {"profile", "provider", "type", "tag"},
	"view":      {},
	"load":      {},
	"rotate":    {"allow-unverified", "passphrase"},
	"rollback":  {},
	"expiry":    {},
	"providers": {"export", "force"},
	"net":       {},
	"validate":  {},
	"audit":     {"notify"},
	"bundle":    {"recipient", "output"},
	"restore":   {"identity"},

	"config check":  {},
	"config render": {"dry-run"},
	"config show":   {},

	"profile add":    {"shared", "key-name"},
	"profile edit":   {"key-scope", "key-name"},
	"profile delete": {"revoke"},

	"host add":    {"hostname", "user", "port", "provider", "token-env", "key-name", "tag"},
	"host edit":   {"hostname", "user", "port", "provider", "token-env", "key-name"},
	"host delete": {"revoke"},

	"notify install": {},
	"notify test":    {},

	"snapshots list":    {},
	"snapshots restore": {},
	"snapshots prune":   {"keep"},

	"knownhosts init": {"all", "force"},
	"knownhosts pin":  {"all", "port", "yes"},
}

// v1Dropped names every v1 flag deliberately NOT carried into Go, with
// the decision that removed it.
//
// It exists because omission is invisible. v1Surface is a transcription, and
// the check below can only compare what was transcribed - so a flag left out of
// it is unverified in both directions at once: nothing notices it is gone, and
// nothing notices if it comes back. --user was recorded that way, as a comment
// next to a shortened list, which documents the decision for a reader and
// asserts nothing. Listing it here makes the removal a checked fact.
var v1Dropped = map[string]string{
	"knownhosts init --user": "D4: there is one trust store now, not one per profile " +
		"plus the user's, so there is nothing left for the flag to select",
}

// goOnly names every verb and flag with no v1 counterpart, against the
// deviation that authorises it. An entry here is a decision someone made; an
// addition without one is a test failure.
var goOnly = map[string]string{
	"key":        "D1 - key add/list/delete, the dangling-key lifecycle v1 had no verb for",
	"key add":    "D1",
	"key list":   "D1",
	"key delete": "D1",
	"show":       "D1 - reconciles manifest, key files, rendered config and trust store in one view",
	"clean":      "D1 - prunes stale pins and records left by deletions",

	"doctor --strict": "D7 - CI gate: escalates every dangling-key state to fatal",

	// Categories group profiles under profiles/<category>/ with one Include per
	// category. v1 had only the flat layout.
	// Bulk key work: rotate a selection instead of one key at a time, and
	// rebuild public keys from their private key or 1Password item.
	"rotate --all":             "bulk rotation - every key a host uses",
	"rotate --category":        "bulk rotation - every key in a category's profiles",
	"rotate --dry-run":         "bulk rotation - list the batch, change nothing",
	"key regen-pub":            "rebuild .pub files from the private key or the 1Password item",
	"key regen-pub --all":      "regen-pub - every key",
	"key regen-pub --category": "regen-pub - every key in a category",
	"key regen-pub --dry-run":  "regen-pub - report only",
	"key regen-pub --yes":      "confirm-before-changing",

	// Git remote modes (3.4.0): profile SSH by default, plain SSH or HTTPS on demand,
	// switched per checkout with an ls-remote check before origin is rewritten.
	"git":               "git remote modes - group",
	"git status":        "git remote modes - each checkout's mode, owner and profile",
	"git use":           "git remote modes - point origin at profile, ssh or https",
	"git use --mode":    "git remote modes - the mode when not given as the first argument",
	"git use --profile": "git remote modes - override the owner-to-profile mapping",
	"git use --dry-run": "git remote modes - show the rewrite, touch nothing",
	"git use --yes":     "confirm-before-changing",

	// Devboxes (3.4.0): a VM's address comes from its hypervisor at connect time.
	"vm":                  "devboxes - group",
	"vm list":             "devboxes - every hypervisor's VMs and the host using each",
	"vm add":              "devboxes - add a VM as a host",
	"vm add --hypervisor": "devboxes - which hypervisor",
	"vm add --vm":         "devboxes - the VM's name",
	"vm add --user":       "devboxes - guest user",
	"vm add --key-name":   "devboxes - key override, as host add",
	"vm add --yes":        "confirm-before-changing",
	"vm docker-context":   "devboxes - Docker context ssh://<alias>",

	// Exports (3.4.0): copies for tools that cannot read the split config. Neither
	// touches ~/.ssh; both refuse a file `config render` owns as their target.
	"config export":                "exports - the config as one file for another tool",
	"config export --flat":         "exports - every host inline, absolute paths, no Include",
	"config export --out":          "exports - target file, or - for stdout",
	"termius":                      "exports - group for the Termius app",
	"termius export":               "exports - Termius CSV import plus the key to attach to each host",
	"termius export --out":         "exports - target file, or - for stdout",
	"termius export --include-git": "exports - also export git hosts, which are not shells",
	"termius export --open":        "exports - macOS: open Termius and show the file in Finder",
	"termius export --skip":        "exports - leave out a named host",
	"termius keys":                 "exports - Termius key label per host; copy one host's private key to the clipboard",
	"termius keys --include-git":   "exports - also list git hosts",
	"termius keys --print":         "exports - print the key instead of copying, with a stderr warning",
	"termius keys --clear":         "exports - empty the clipboard",
	"termius keys --clear-after":   "exports - auto-clear the clipboard after a delay",

	// Cloudflare Access (3.4.0): a host reached through cloudflared, rendered by sshmgr since
	// raw_options may not set a ProxyCommand.
	"host add --proxy":  "cloudflare access - route the host through cloudflared",
	"host edit --proxy": "cloudflare access - set or remove (none) the proxy",
	"host edit --tag":   "G7 - replace a host's tags; nothing else could take one off",
	"host edit --untag": "G7 - remove one tag from a host",

	// Compact host specs (unreleased): add-or-update one host or many from
	// `<alias> <host>[:port] <user> [role]`.
	"host apply": "host specs - upsert hosts from compact specs, a file or JSON",

	"profile add --category":  "categories - file a new profile under profiles/<category>/",
	"profile edit --category": "categories - move a profile's keys and records under profiles/<category>/",

	// Confirmation and safety flags. v1 prompted; the Go verbs take an
	// explicit --yes so they are usable from a script, and refuse to destroy key
	// material without a backup path.
	// Every verb that changes ~/.ssh now confirms first when there is a terminal
	// to ask at, and --yes is how a script says "go ahead" explicitly rather than
	// relying on the absence of one. v1 prompted only on the destructive
	// verbs and had no flag at all.
	"reconcile --yes":                "confirm-before-changing; see confirmChange",
	"keygen --yes":                   "confirm-before-changing; also answers the per-key overwrite prompts",
	"import --yes":                   "confirm-before-changing",
	"deploy --yes":                   "confirm-before-changing",
	"clean --yes":                    "confirm-before-changing",
	"config render --yes":            "confirm-before-changing",
	"knownhosts init --yes":          "confirm-before-changing",
	"migrate --yes":                  "confirm-before-changing",
	"notify install --yes":           "confirm-before-changing",
	"keygen --no-key-backup":         "refuses to destroy key material unless told; no v1 counterpart",
	"rotate --yes":                   "confirmation flag",
	"rollback --yes":                 "confirmation flag",
	"restore --yes":                  "confirmation flag",
	"snapshots restore --yes":        "confirmation flag",
	"profile delete --yes":           "confirmation flag",
	"profile delete --purge":         "D1 - removes the key files, not just the manifest entry",
	"profile delete --no-key-backup": "as keygen",
	"host delete --yes":              "confirmation flag",
	"host delete --purge":            "D1",
	"host delete --no-key-backup":    "as keygen",

	"bundle --keep":          "retention for the encrypted bundles",
	"clean --dry-run":        "D1",
	"clean --adopt":          "D1",
	"rotate --no-key-backup": "as keygen",
}

// walk collects the tree as "parent child" -> long flag names.
func walk(c *cobra.Command, prefix string, out map[string][]string) {
	for _, sub := range c.Commands() {
		if sub.Hidden || sub.Name() == "help" || sub.Name() == "completion" {
			continue
		}
		name := strings.TrimSpace(prefix + " " + sub.Name())
		var flags []string
		sub.LocalFlags().VisitAll(func(f *pflag.Flag) {
			if f.Name != "help" {
				flags = append(flags, f.Name)
			}
		})
		sort.Strings(flags)
		out[name] = flags
		walk(sub, name, out)
	}
}

func TestTheCommandSurfaceMatchesTheOneItReplaced(t *testing.T) {
	got := map[string][]string{}
	walk(newRootCmd(), "", got)

	// Groups exist only to hold subcommands; v1 had them as sub-apps
	// with no flags of their own.
	groups := map[string]bool{"config": true, "profile": true, "host": true,
		"notify": true, "snapshots": true, "knownhosts": true, "key": true}

	// 1. Everything v1 had, Go still has - verb and flag.
	for verb, want := range v1Surface {
		have, ok := got[verb]
		if !ok {
			t.Errorf("%q is in v1's CLI and gone from the Go tree", verb)
			continue
		}
		for _, f := range want {
			if !contains(have, f) {
				t.Errorf("%s: --%s was declared in v1 and is missing here (have: %v)", verb, f, have)
			}
		}
	}

	// 2. Nothing widened without a written reason.
	for verb, flags := range got {
		if groups[verb] {
			continue
		}
		known, inV1 := v1Surface[verb]
		if !inV1 {
			if _, allowed := goOnly[verb]; !allowed {
				t.Errorf("%q has no v1 counterpart and no entry in goOnly; "+
					"add the deviation that authorises it", verb)
			}
			continue
		}
		for _, f := range flags {
			if contains(known, f) {
				continue
			}
			if _, allowed := goOnly[verb+" --"+f]; !allowed {
				t.Errorf("%s: --%s is not in v1 and has no entry in goOnly; "+
					"add the deviation that authorises it", verb, f)
			}
		}
	}

	// 3. goOnly is the record of why each addition exists, so it must not carry
	//    entries for things that are not there. An unused allowlist entry is
	//    silently ignored - three sat here claiming a --no-passphrase that was
	//    dropped in the 2.0.0 rewrite, and docs/features.md documented it because
	//    this table said it existed.
	present := map[string]bool{}
	for verb, flags := range got {
		present[verb] = true
		for _, f := range flags {
			present[verb+" --"+f] = true
		}
	}
	for entry := range goOnly {
		if !present[entry] {
			t.Errorf("goOnly has an entry for %q, which does not exist. "+
				"Remove it: an unused justification reads as documentation of a real flag.", entry)
		}
	}

	// 4. A dropped flag stays dropped, and every drop is a recorded decision.
	//    Both halves matter: re-adding one silently would undo the design change
	//    that removed it, and an entry here for a flag that is present would mean
	//    the record and the tree disagree about what the tool does.
	for entry, why := range v1Dropped {
		if present[entry] {
			t.Errorf("%q is listed in v1Dropped (%s) but exists in the Go tree. "+
				"Either the removal was reverted, or the record is stale.", entry, why)
		}
		verb := strings.TrimSpace(strings.Split(entry, " --")[0])
		if _, ok := got[verb]; !ok {
			t.Errorf("v1Dropped names %q, whose verb %q does not exist; "+
				"the entry can no longer be checked against anything", entry, verb)
		}
	}

	// 5. Every command explains itself. A verb with no Short is invisible in
	//    `sshmgr --help`, which is the only place most users look.
	var noShort []string
	var check func(c *cobra.Command, prefix string)
	check = func(c *cobra.Command, prefix string) {
		for _, sub := range c.Commands() {
			if sub.Hidden || sub.Name() == "help" || sub.Name() == "completion" {
				continue
			}
			name := strings.TrimSpace(prefix + " " + sub.Name())
			if strings.TrimSpace(sub.Short) == "" {
				noShort = append(noShort, name)
			}
			sub.LocalFlags().VisitAll(func(f *pflag.Flag) {
				if f.Name != "help" && strings.TrimSpace(f.Usage) == "" {
					noShort = append(noShort, name+" --"+f.Name)
				}
			})
			check(sub, name)
		}
	}
	check(newRootCmd(), "")
	if len(noShort) > 0 {
		sort.Strings(noShort)
		t.Errorf("these carry no description and so are undocumented in --help: %v", noShort)
	}
}

// pflag reads the first `backticked` word of a flag's usage as the value's name,
// so "see `sshmgr providers`" printed as "--provider sshmgr providers" in --help.
// A flag that names a value does it with a plain word instead.
func TestFlagUsageHasNoBackticks(t *testing.T) {
	var bad []string
	inspected := 0
	var check func(c *cobra.Command, prefix string)
	check = func(c *cobra.Command, prefix string) {
		c.LocalFlags().VisitAll(func(f *pflag.Flag) {
			inspected++
			if strings.Contains(f.Usage, "`") {
				bad = append(bad, strings.TrimSpace(prefix+" --"+f.Name))
			}
		})
		for _, sub := range c.Commands() {
			check(sub, strings.TrimSpace(prefix+" "+sub.Name()))
		}
	}
	check(newRootCmd(), "")
	if inspected < 100 {
		t.Fatalf("inspected only %d flags; the walk is not reaching the tree", inspected)
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		t.Errorf("these flags show a backticked phrase as their value name in --help: %v", bad)
	}
}

// The root's own contract: --version answers without a manifest, and an unknown
// verb is an error rather than a silent no-op.
func TestTheRootAnswersVersionAndRejectsAnUnknownVerb(t *testing.T) {
	editHome(t)
	if out := run(t, "--version"); !strings.Contains(out, "sshmgr") {
		t.Errorf("--version printed %q", out)
	}
	if _, err := runErr(t, "no-such-verb"); err == nil {
		t.Error("an unknown verb should be an error")
	}
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}
