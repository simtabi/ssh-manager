package web

import "embed"

// The templates and the assets are compiled into the binary, so `serve` needs
// nothing on disk and the page needs nothing from the network.
//
//go:embed templates
var templateFS embed.FS

//go:embed assets
var assetFS embed.FS
