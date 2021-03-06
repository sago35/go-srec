package srec

import (
	"fmt"
	"strings"
	"testing"
)

func TestSrecBasic(t *testing.T) {
	src := []string{
		`S11301007A07000FFF0E7A00000001627A01000FE7`,
		`S11300001285F245F2212226A00042429000823756`,
		`S2140C040021002C0000000000180000000000000670`,
		`S315CAFE0120AA55AA55AA55AA55AA55AA55AA55AA5509`,

		// https://en.wikipedia.org/wiki/SREC_(file_format)
		// S19-style 16-bit address records
		`S00F000068656C6C6F202020202000003C`,
		`S11F00007C0802A6900100049421FFF07C6C1B787C8C23783C6000003863000026`,
		`S11F001C4BFFFFE5398000007D83637880010014382100107C0803A64E800020E9`,
		`S111003848656C6C6F20776F726C642E0A0042`,
		`S5030003F9`,
		`S9030000FC`,

		// S28-style 24-bit address records
		`S00F000068656C6C6F202020202000003C`,
		`S2200000007C0802A6900100049421FFF07C6C1B787C8C23783C6000003863000025`,
		`S22000001C4BFFFFE5398000007D83637880010014382100107C0803A64E800020E8`,
		`S21200003848656C6C6F20776F726C642E0A0041`,
		`S5030003F9`,
		`S804000000FB`,

		// S37-style 32-bit address records
		`S00F000068656C6C6F202020202000003C`,
		`S321000000007C0802A6900100049421FFF07C6C1B787C8C23783C6000003863000024`,
		`S3210000001C4BFFFFE5398000007D83637880010014382100107C0803A64E800020E7`,
		`S3130000003848656C6C6F20776F726C642E0A0040`,
		`S5030003F9`,
		`S70500000000FA`,
	}
	sr := NewScanner(strings.NewReader(strings.Join(src, "\n")))

	for i, s := range src {
		ok := sr.Scan()
		if !ok {
			t.Errorf("%d) sr.Scan() failed", i)
		}

		if g, e := sr.Srec().String(), s; g != e {
			t.Errorf("%d) got %q, want %q", i, g, e)
		}

		if g, e := fmt.Sprintf("%02X", sr.Srec().CalcChecksum()), s[len(s)-2:]; g != e {
			t.Errorf("%d) got %q, want %q", i, g, e)
		}
	}
}

func ExampleScan() {
	src := "S00F000068656C6C6F202020202000003C\n"
	src += "S11F00007C0802A6900100049421FFF07C6C1B787C8C23783C6000003863000026\n"
	src += "S9030000FC\n"

	sr := NewScanner(strings.NewReader(src))
	for sr.Scan() {
		fmt.Println(sr.Srec())
	}

	// Output:
	// S00F000068656C6C6F202020202000003C
	// S11F00007C0802A6900100049421FFF07C6C1B787C8C23783C6000003863000026
	// S9030000FC
}

func ExampleNewSrec() {
	s1 := NewS1(0x0000001C, []byte{0x4B, 0xFF, 0xFF, 0xE5, 0x39, 0x80, 0x00, 0x00, 0x7D, 0x83, 0x63, 0x78, 0x80, 0x01, 0x00, 0x14, 0x38, 0x21, 0x00, 0x10, 0x7C, 0x08, 0x03, 0xA6, 0x4E, 0x80, 0x00, 0x20})
	fmt.Println(s1)

	s2 := NewS2(0x0000001C, []byte{0x4B, 0xFF, 0xFF, 0xE5, 0x39, 0x80, 0x00, 0x00, 0x7D, 0x83, 0x63, 0x78, 0x80, 0x01, 0x00, 0x14, 0x38, 0x21, 0x00, 0x10, 0x7C, 0x08, 0x03, 0xA6, 0x4E, 0x80, 0x00, 0x20})
	fmt.Println(s2)

	s3 := NewS3(0x0000001C, []byte{0x4B, 0xFF, 0xFF, 0xE5, 0x39, 0x80, 0x00, 0x00, 0x7D, 0x83, 0x63, 0x78, 0x80, 0x01, 0x00, 0x14, 0x38, 0x21, 0x00, 0x10, 0x7C, 0x08, 0x03, 0xA6, 0x4E, 0x80, 0x00, 0x20})
	fmt.Println(s3)

	// Output:
	// S11F001C4BFFFFE5398000007D83637880010014382100107C0803A64E800020E9
	// S22000001C4BFFFFE5398000007D83637880010014382100107C0803A64E800020E8
	// S3210000001C4BFFFFE5398000007D83637880010014382100107C0803A64E800020E7
}
