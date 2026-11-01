// Package web embeds KONE's offline management application.
// Frontend sources live in web/src; npm run build refreshes dist.
package web

import "embed"

// Files contains the built application and its local assets.
//
//go:embed all:dist
var Files embed.FS

// MacOSTrayScript is the fixed AppKit companion; stdin carries state only.
//
//go:embed native/tray-darwin.js
var MacOSTrayScript string
