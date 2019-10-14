package srec

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// Scanner ...
type Scanner struct {
	scanner *bufio.Scanner
	srec    *Srec
	err     error
}

// Srec ...
type Srec struct {
	Type     string
	Length   int
	Address  uint32
	Data     []byte
	Checksum byte
}

// NewScanner ...
func NewScanner(r io.Reader) *Scanner {
	return &Scanner{
		scanner: bufio.NewScanner(r),
	}
}

const (
	s0 = `S0`
	s1 = `S1`
	s2 = `S2`
	s3 = `S3`
	s4 = `S4` // reserved
	s5 = `S5`
	s6 = `S6`
	s7 = `S7`
	s8 = `S8`
	s9 = `S9`
)

// Errors returned by Scanner.
var (
	ErrInvalidType = errors.New("srec.Scanner: invalid type")
)

// Scan ...
func (s *Scanner) Scan() bool {
	ok := s.scanner.Scan()
	if !ok {
		s.err = s.scanner.Err()
		return false
	}

	t := s.scanner.Text()
	sr := &Srec{
		Type:   t[0:2],
		Length: readLength(t[2:]),
	}

	addrLen := 0
	csLen := 1

	switch sr.Type {
	case s0, s1, s9:
		addrLen = 2
		sr.Address = readAddress(t[4:], addrLen)
	case s2, s8:
		addrLen = 3
		sr.Address = readAddress(t[4:], addrLen)
	case s3, s7:
		addrLen = 4
		sr.Address = readAddress(t[4:], addrLen)
	default:
		// skip
	}

	sr.Data = readData(t[4+addrLen*2:], sr.Length-addrLen-csLen)
	sr.Checksum = readChecksum(t[2+sr.Length*2:])

	s.srec = sr

	return true
}

// Srec ...
func (s *Scanner) Srec() *Srec {
	return s.srec
}

func readLength(src string) int {
	dst := make([]byte, 1)

	_, err := hex.Decode(dst, []byte(src[0:2]))
	if err != nil {
		return 0
	}

	return int(dst[0])
}

func readAddress(src string, length int) uint32 {
	dst := make([]byte, length)
	_, err := hex.Decode(dst, []byte(src[0:length*2]))
	if err != nil {
		return 0
	}

	ret := uint32(dst[0])
	for i, d := range dst[1:] {
		if i >= 4 {
			break
		}

		ret <<= 8
		ret += uint32(d)
	}

	return ret
}

func readData(src string, length int) []byte {
	dst := make([]byte, length)
	_, err := hex.Decode(dst, []byte(src[0:length*2]))
	if err != nil {
		return nil
	}

	return dst
}

func readChecksum(src string) byte {
	dst := make([]byte, 1)
	_, err := hex.Decode(dst, []byte(src[0:2]))
	if err != nil {
		return 0
	}

	return dst[0]
}

// CalcChecksum ...
func (sr *Srec) CalcChecksum() byte {
	cs := byte(sr.Length)

	cs += byte(sr.Address >> 24)
	cs += byte(sr.Address >> 16)
	cs += byte(sr.Address >> 8)
	cs += byte(sr.Address)

	for _, d := range sr.Data {
		cs += d
	}

	return ^cs
}

func (sr *Srec) String() string {
	ret := fmt.Sprintf(`%s%02X`, sr.Type, sr.Length)
	switch sr.Type {
	case s0, s1, s9:
		ret += fmt.Sprintf(`%04X`, sr.Address)
	case s2, s8:
		ret += fmt.Sprintf(`%06X`, sr.Address)
	case s3, s7:
		ret += fmt.Sprintf(`%08X`, sr.Address)
	default:
		// skip
	}

	for _, d := range sr.Data {
		ret += fmt.Sprintf(`%02X`, d)
	}

	ret += fmt.Sprintf(`%02X`, sr.Checksum)

	return ret
}
