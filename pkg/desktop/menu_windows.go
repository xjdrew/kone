package desktop

import (
	"errors"
	"math"
	"unsafe"

	"golang.org/x/sys/windows"
)

var trayGDI32 = windows.NewLazySystemDLL("gdi32.dll")

type trayMenuItemInfo struct {
	Size, Mask, Type, State, ID uint32
	Submenu, Checked, Unchecked uintptr
	Data                        uintptr
	Text                        *uint16
	TextLength                  uint32
	Bitmap                      uintptr
}

type trayBitmapInfo struct {
	Size          uint32
	Width, Height int32
	Planes, Bits  uint16
	Compression   uint32
	ImageSize     uint32
	XPels, YPels  int32
	Used, Needed  uint32
}

type trayMenu struct {
	handle  uintptr
	bitmaps []uintptr
}

func (menu *trayMenu) close() {
	if menu.handle != 0 {
		trayUser32.NewProc("DestroyMenu").Call(menu.handle)
		menu.handle = 0
	}
	for _, bitmap := range menu.bitmaps {
		trayGDI32.NewProc("DeleteObject").Call(bitmap)
	}
	menu.bitmaps = nil
}

// Keep Windows responsible for menu layout, keyboard navigation, selection,
// disabled text and high-contrast themes. Bitmaps decorate ordinary text items.
func createTrayMenu(actions TrayActions, size int) (_ *trayMenu, result error) {
	menu := new(trayMenu)
	menu.handle, _, _ = trayUser32.NewProc("CreatePopupMenu").Call()
	if menu.handle == 0 {
		return nil, errors.New("could not create the KONE tray menu")
	}
	defer func() {
		if result != nil {
			menu.close()
		}
	}()
	status := nativeTrayStatus(actions)
	for _, item := range []struct {
		id      uintptr
		label   string
		enabled bool
	}{
		{1, "Open KONE", actions.Open != nil},
		{},
		{4, "Start capture", status.CanStart},
		{2, "Pause capture", status.CanPause},
		{},
		{5, "Diagnostics", status.CanDiagnose},
		{},
		{3, "Exit KONE", actions.Exit != nil},
	} {
		flags := uintptr(0)
		if item.id == 0 {
			flags = 0x800 // MF_SEPARATOR
		} else if !item.enabled {
			flags = 3 // MF_GRAYED | MF_DISABLED
		}
		added, _, _ := trayUser32.NewProc("AppendMenuW").Call(menu.handle, flags, item.id, uintptr(unsafe.Pointer(trayUTF16(item.label))))
		if added == 0 {
			return nil, errors.New("could not add a KONE tray menu item")
		}
		if item.id == 0 {
			continue
		}
		bitmap, err := createTrayMenuBitmap(item.id, size, item.enabled)
		if err != nil {
			return nil, err
		}
		menu.bitmaps = append(menu.bitmaps, bitmap)
		info := trayMenuItemInfo{Size: uint32(unsafe.Sizeof(trayMenuItemInfo{})), Mask: 0x80, Bitmap: bitmap} // MIIM_BITMAP
		set, _, _ := trayUser32.NewProc("SetMenuItemInfoW").Call(menu.handle, item.id, 0, uintptr(unsafe.Pointer(&info)))
		if set == 0 {
			return nil, errors.New("could not attach a KONE tray menu icon")
		}
	}
	trayUser32.NewProc("SetMenuDefaultItem").Call(menu.handle, 1, 0)
	return menu, nil
}

func createTrayMenuBitmap(id uintptr, size int, enabled bool) (uintptr, error) {
	if size < 8 || size > 128 {
		return 0, errors.New("invalid tray menu icon dimensions")
	}
	info := trayBitmapInfo{Size: uint32(unsafe.Sizeof(trayBitmapInfo{})), Width: int32(size), Height: -int32(size), Planes: 1, Bits: 32}
	var bits unsafe.Pointer
	bitmap, _, _ := trayGDI32.NewProc("CreateDIBSection").Call(0, uintptr(unsafe.Pointer(&info)), 0, uintptr(unsafe.Pointer(&bits)), 0, 0)
	if bitmap == 0 {
		return 0, errors.New("could not allocate a KONE tray menu icon")
	}
	pixels := unsafe.Slice((*uint32)(bits), size*size)
	if id != 1 {
		colorIndex := uintptr(7) // COLOR_MENUTEXT, including high-contrast colors.
		if !enabled {
			colorIndex = 17 // COLOR_GRAYTEXT
		}
		color, _, _ := trayUser32.NewProc("GetSysColor").Call(colorIndex)
		drawTrayMenuGlyph(pixels, size, id, uint32(color))
		return bitmap, nil
	}
	icon, err := loadTrayIconSize(0, uintptr(size), uintptr(size))
	if err != nil {
		trayGDI32.NewProc("DeleteObject").Call(bitmap)
		return 0, err
	}
	defer trayUser32.NewProc("DestroyIcon").Call(icon)
	dc, _, _ := trayGDI32.NewProc("CreateCompatibleDC").Call(0)
	if dc == 0 {
		trayGDI32.NewProc("DeleteObject").Call(bitmap)
		return 0, errors.New("could not draw the KONE tray menu icon")
	}
	defer trayGDI32.NewProc("DeleteDC").Call(dc)
	previous, _, _ := trayGDI32.NewProc("SelectObject").Call(dc, bitmap)
	drawn, _, _ := trayUser32.NewProc("DrawIconEx").Call(dc, 0, 0, icon, uintptr(size), uintptr(size), 0, 0, 3)
	trayGDI32.NewProc("SelectObject").Call(dc, previous)
	if drawn == 0 {
		trayGDI32.NewProc("DeleteObject").Call(bitmap)
		return 0, errors.New("could not draw the KONE tray menu icon")
	}
	return bitmap, nil
}

// Rasterize simple 16-unit outlines with antialiasing and premultiplied alpha.
// This stays sharp at each monitor's DPI without adding image resources.
func drawTrayMenuGlyph(pixels []uint32, size int, id uintptr, color uint32) {
	var lines [][4]float64
	switch id {
	case 4: // Play.
		lines = [][4]float64{{5, 3, 13, 8}, {13, 8, 5, 13}, {5, 13, 5, 3}}
	case 2: // Pause.
		lines = [][4]float64{{5.5, 3.5, 5.5, 12.5}, {10.5, 3.5, 10.5, 12.5}}
	case 5: // Magnifier.
		lines = [][4]float64{{10, 10, 13.5, 13.5}}
	case 3: // Exit through a door.
		lines = [][4]float64{{6, 3, 3, 3}, {3, 3, 3, 13}, {3, 13, 6, 13}, {7, 8, 14, 8}, {11, 5, 14, 8}, {14, 8, 11, 11}}
	}
	for y := range size {
		for x := range size {
			covered := uint32(0)
			for sy := range 4 {
				for sx := range 4 {
					px := (float64(x) + (float64(sx)+0.5)/4) * 16 / float64(size)
					py := (float64(y) + (float64(sy)+0.5)/4) * 16 / float64(size)
					inside := id == 5 && math.Abs(math.Hypot(px-6.8, py-6.8)-4.3) <= 0.8
					for _, line := range lines {
						dx, dy := line[2]-line[0], line[3]-line[1]
						t := max(0, min(1, ((px-line[0])*dx+(py-line[1])*dy)/(dx*dx+dy*dy)))
						inside = inside || math.Hypot(px-line[0]-t*dx, py-line[1]-t*dy) <= 0.8
					}
					if inside {
						covered++
					}
				}
			}
			alpha := covered * 255 / 16
			r, g, b := color&255, (color>>8)&255, (color>>16)&255
			pixels[y*size+x] = alpha<<24 | (r*alpha/255)<<16 | (g*alpha/255)<<8 | b*alpha/255
		}
	}
}

func trayMenuIconSize(hwnd uintptr) int {
	dpi := uintptr(96)
	if proc := trayUser32.NewProc("GetDpiForWindow"); proc.Find() == nil {
		if value, _, _ := proc.Call(hwnd); value != 0 {
			dpi = value
		}
	}
	var size uintptr
	if proc := trayUser32.NewProc("GetSystemMetricsForDpi"); proc.Find() == nil {
		size, _, _ = proc.Call(49, dpi) // SM_CXSMICON
	} else {
		size, _, _ = trayUser32.NewProc("GetSystemMetrics").Call(49)
	}
	if size < 8 || size > 128 {
		return 16
	}
	return int(size)
}

func invokeWindowsTrayMenuAction(actions TrayActions, id uintptr) {
	if id == 4 || id == 2 {
		// Lifecycle state may have changed while Windows was tracking the menu.
		status := nativeTrayStatus(actions)
		if id == 4 && !status.CanStart || id == 2 && !status.CanPause {
			return
		}
	}
	invokeTrayAction(actions, id)
}
