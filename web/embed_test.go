package web

import (
	"bytes"
	"encoding/base64"
	"image/png"
	"strings"
	"testing"
)

func TestNativeTrayAssetsAreEmbeddedAndTemplateIsComplete(t *testing.T) {
	config, err := png.DecodeConfig(bytes.NewReader(WindowsTrayIcon))
	if err != nil || config.Width != 32 || config.Height != 32 {
		t.Fatalf("invalid Windows tray PNG: %v, %v", config, err)
	}
	if strings.Contains(MacOSTrayScript, "__KONE_TRAY_ICON_BASE64__") ||
		!strings.Contains(MacOSTrayScript, base64.StdEncoding.EncodeToString(macOSTrayIcon)) {
		t.Fatal("macOS companion must embed its template image")
	}
	config, err = png.DecodeConfig(bytes.NewReader(macOSTrayIcon))
	if err != nil || config.Width != 44 || config.Height != 44 {
		t.Fatalf("invalid macOS template PNG: %v, %v", config, err)
	}
}
