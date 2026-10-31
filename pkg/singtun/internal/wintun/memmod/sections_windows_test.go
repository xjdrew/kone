// SPDX-License-Identifier: MIT
package memmod

import (
	"testing"
	"unsafe"
)

// A PE image lives in one Go byte allocation before loading. The old giant
// array cast claimed memory beyond that allocation even for a small PE table,
// and crashed under -race/checkptr before Wintun could create an adapter.
func TestSectionsStayWithinImageAllocation(t *testing.T) {
	for _, count := range []int{0, 1, 8} {
		offset := unsafe.Offsetof(IMAGE_NT_HEADERS{}.OptionalHeader) + unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{})
		image := make([]byte, int(offset)+count*int(unsafe.Sizeof(IMAGE_SECTION_HEADER{})))
		header := (*IMAGE_NT_HEADERS)(unsafe.Pointer(&image[0]))
		header.FileHeader.SizeOfOptionalHeader = uint16(unsafe.Sizeof(IMAGE_OPTIONAL_HEADER{}))
		header.FileHeader.NumberOfSections = uint16(count)
		sections := header.Sections()
		if len(sections) != count {
			t.Fatalf("sections=%d, want %d", len(sections), count)
		}
		for i := range sections {
			sections[i].VirtualAddress = uint32(i + 1)
		}
		for i, section := range header.Sections() {
			if section.VirtualAddress != uint32(i+1) {
				t.Fatal("section table did not alias its image")
			}
		}
	}
}
