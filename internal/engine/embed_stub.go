//go:build !bundled

package engine

// bundledEngine returns the path to the embedded frozen engine, or "" when this
// build has no engine bundled. The real implementation (a go:embed extractor) is
// compiled in under the `bundled` build tag for release builds.
func bundledEngine() string { return "" }
