// Command tablervendor vendors the Tabler assets the web UI embeds.
//
// It is run by a maintainer through the Makefile, never by `go build`:
//
//	make tabler-update   # move to the newest @tabler/core and @tabler/icons-sprite
//	make tabler-vendor   # re-vendor exactly what TABLER_VERSION pins
//
// Both download the npm tarballs, verify each against the registry's sha512
// integrity before extracting anything, and rewrite every vendored file, the
// licence texts, MANIFEST.sha256 and the repository's THIRD_PARTY_NOTICES.md
// together, so a version can never move without its notices and hashes.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/simtabi/ssh-manager/src/v3/internal/tabler"
)

func main() {
	var (
		latest bool
		check  bool
		root   string
	)
	flag.BoolVar(&latest, "latest", false, "resolve the newest releases and pin them before vendoring")
	flag.BoolVar(&check, "check", false, "only report, as GitHub warnings, whether the pin is behind the newest releases")
	flag.StringVar(&root, "root", "..", "repository root (the Makefile runs this from src/)")
	flag.Parse()

	v := &tabler.Vendor{
		Root:     root,
		AssetDir: filepath.Join(root, "src", "internal", "web", "assets", "vendor"),
		Fetch:    tabler.HTTPFetcher{},
		Log:      func(format string, a ...any) { fmt.Fprintf(os.Stderr, format+"\n", a...) },
	}
	if check {
		behind, err := v.Check()
		if err != nil {
			fmt.Fprintln(os.Stderr, "tablervendor:", err)
			os.Exit(1)
		}
		for _, line := range behind {
			fmt.Println("::warning title=Tabler update available::" + line)
		}
		if len(behind) == 0 {
			fmt.Println("Tabler is at the newest releases.")
		}
		return
	}
	if err := v.Run(latest); err != nil {
		fmt.Fprintln(os.Stderr, "tablervendor:", err)
		os.Exit(1)
	}
}
