// Package web embeds KONE's offline management application.
// Frontend sources live in web/src; npm run build refreshes dist.
package web

import (
	"embed"
	"encoding/base64"
	"strings"
)

// Files contains the built application and its local assets.
//
//go:embed all:dist
var Files embed.FS

// WindowsTrayIcon is also used by builds without executable resources, such as
// the desktop package's native tray tests.
//
//go:embed native/tray-windows.png
var WindowsTrayIcon []byte

//go:embed native/tray.png
var macOSTrayIcon []byte

// macOSTrayScript is the fixed AppKit companion; stdin carries state only.
//
//go:embed native/tray-darwin.js
var macOSTrayScript string

// MacOSTrayScript embeds the template image as data, without external file paths.
var MacOSTrayScript = strings.Replace(macOSTrayScript, "__KONE_TRAY_ICON_BASE64__", base64.StdEncoding.EncodeToString(macOSTrayIcon), 1)
