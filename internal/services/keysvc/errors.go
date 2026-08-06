package keysvc

import "fmt"

// errUnknown is the one "nothing matched" error, so `key list`, `show` and
// `key delete` all reject a typo the same way.
func errUnknown(selector string) error {
	return fmt.Errorf("no key, profile or host matches %q", selector)
}
