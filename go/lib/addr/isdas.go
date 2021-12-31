// Copyright 2016 ETH Zurich
// Copyright 2018 ETH Zurich, Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package addr

import (
	"encoding"
	"encoding/binary"
	"flag"
	"fmt"
	"strconv"
	"strings"

	"github.com/scionproto/scion/go/lib/serrors"
)

const (
	IABytes       = 8
	ISDBits       = 16
	ASBits        = 48
	BGPASBits     = 32
	MaxISD    ISD = (1 << ISDBits) - 1
	MaxAS     AS  = (1 << ASBits) - 1
	MaxBGPAS  AS  = (1 << BGPASBits) - 1

	asPartBits = 16
	asPartBase = 16
	asPartMask = (1 << asPartBits) - 1
	asParts    = ASBits / asPartBits

	ISDFmtPrefix = "ISD"
	ASFmtPrefix  = "AS"
)

// ISD is the ISolation Domain identifier. See formatting and allocations here:
// https://github.com/scionproto/scion/wiki/ISD-and-AS-numbering#isd-numbers
type ISD uint16

// ISDFromString parses an ISD from a decimal string.
func ISDFromString(s string) (ISD, error) {
	isd, err := strconv.ParseUint(s, 10, ISDBits)
	if err != nil {
		// err.Error() will contain the original value
		return 0, serrors.WrapStr("Unable to parse ISD", err)
	}
	return ISD(isd), nil
}

// ISDFromFileFmt parses an ISD from a file-format string. If prefix is true,
// an 'ISD' prefix is expected and stripped before parsing.
func ISDFromFileFmt(s string, prefix bool) (ISD, error) {
	if prefix {
		if !strings.HasPrefix(s, ISDFmtPrefix) {
			return 0, serrors.New("prefix missing", "prefix", ISDFmtPrefix, "raw", s)
		}
		s = s[len(ISDFmtPrefix):]
	}
	return ISDFromString(s)
}

func (isd ISD) String() string {
	return strconv.FormatUint(uint64(isd), 10)
}

var _ encoding.TextUnmarshaler = (*AS)(nil)

// AS is the Autonomous System idenifier. See formatting and allocations here:
// https://github.com/scionproto/scion/wiki/ISD-and-AS-numbering#as-numbers
type AS uint64

// ASFromString parses an AS from a decimal (in the case of the 32bit BGP AS
// number space) or ipv6-style hex (in the case of SCION-only AS numbers)
// string.
func ASFromString(s string) (AS, error) {
	return asParse(s, ":")
}

// ASFromFileFmt parses an AS from a file-format string. This is the same
// format as ASFromString expects, with ':' replaced by '_'. If prefix is true,
// an 'AS' prefix is expected and stripped before parsing.
func ASFromFileFmt(s string, prefix bool) (AS, error) {
	if prefix {
		if !strings.HasPrefix(s, ASFmtPrefix) {
			return 0, serrors.New("prefix missing", "prefix", ASFmtPrefix, "raw", s)
		}
		s = s[len(ASFmtPrefix):]
	}
	return asParse(s, "_")
}

func asParse(s string, sep string) (AS, error) {
	if !strings.Contains(s, sep) {
		// Must be a BGP AS, parse as 32-bit decimal number
		as, err := strconv.ParseUint(s, 10, BGPASBits)
		if err != nil {
			// err.Error() will contain the original value
			return 0, serrors.WrapStr("Unable to parse AS", err)
		}
		return AS(as), nil
	}
	parts := strings.Split(s, sep)
	if len(parts) != asParts {
		return 0, serrors.New("unable to parse AS: wrong number of separators",
			"expected", asParts, "actual", len(parts), "sep", sep, "raw", s)
	}
	var as AS
	for i := 0; i < asParts; i++ {
		as <<= asPartBits
		v, err := strconv.ParseUint(parts[i], asPartBase, asPartBits)
		if err != nil {
			return 0, serrors.WrapStr("Unable to parse AS part", err, "raw", s)
		}
		as |= AS(v)
	}
	return as, nil
}

func (as AS) String() string {
	return as.fmt(':')
}

// FileFmt formats an AS for use in a file name, using '_' instead of ':' as
// the separator for SCION-only AS numbers.
func (as AS) FileFmt() string {
	return as.fmt('_')
}

func (as AS) fmt(sep byte) string {
	if !as.inRange() {
		return fmt.Sprintf("%d [Illegal AS: larger than %d]", as, MaxAS)
	}
	// Format BGP ASes as decimal
	if as <= MaxBGPAS {
		return strconv.FormatUint(uint64(as), 10)
	}
	// Format all other ASes as 'sep'-separated hex.
	const maxLen = len("ffff:ffff:ffff")
	b := make([]byte, 0, maxLen)
	for i := 0; i < asParts; i++ {
		if i > 0 {
			b = append(b, sep)
		}
		shift := uint(asPartBits * (asParts - i - 1))
		s := strconv.FormatUint(uint64(as>>shift)&asPartMask, asPartBase)
		b = append(b, s...)
	}
	return string(b)
}

func (as AS) inRange() bool {
	return as <= MaxAS
}

func (as AS) MarshalText() ([]byte, error) {
	if !as.inRange() {
		return nil, serrors.New("invalid AS", "max", MaxAS, "actual", as)
	}
	return []byte(as.String()), nil
}

func (as *AS) UnmarshalText(text []byte) error {
	newAS, err := ASFromString(string(text))
	if err != nil {
		return err
	}
	*as = newAS
	return nil
}

var _ fmt.Stringer = IAInt(0)
var _ encoding.TextUnmarshaler = (*IAInt)(nil)
var _ flag.Value = (*IAInt)(nil)

// IAInt represents the ISD (ISolation Domain) and AS (Autonomous System) Id of a given SCION AS.
// The highest 16 bit form the ISD number and the lower 48 bits form the AS number.
type IAInt uint64

func (ia IAInt) I() ISD {
	return ISD(ia >> ASBits)
}

func (ia IAInt) A() AS {
	return AS(ia) & MaxAS
}

func (ia IAInt) MarshalText() ([]byte, error) {
	return []byte(ia.String()), nil
}

func (ia *IAInt) UnmarshalText(b []byte) error {
	parts := strings.Split(string(b), "-")
	if len(parts) != 2 {
		return serrors.New("Invalid ISD-AS", "raw", b)
	}
	isd, err := ISDFromString(parts[0])
	if err != nil {
		return err
	}
	as, err := ASFromString(parts[1])
	if err != nil {
		return err
	}
	*ia = NewIAInt(isd, as)
	return nil
}

func IAFromRaw(b []byte) IAInt {
	return IAInt(binary.BigEndian.Uint64(b))
}

// IAFromString parses an IA from a string of the format 'ia-as'.
func IAFromString(s string) (IAInt, error) {
	parts := strings.Split(s, "-")
	if len(parts) != 2 {
		return 0, serrors.New("Invalid ISD-AS", "raw", s)
	}
	isd, err := ISDFromString(parts[0])
	if err != nil {
		return 0, err
	}
	as, err := ASFromString(parts[1])
	if err != nil {
		return 0, err
	}
	return IAInt(isd)<<ASBits | IAInt(as&MaxAS), nil
}

// IAFromFileFmt parses an IAInt from a file-format
func IAFromFileFmt(s string, prefixes bool) (IAInt, error) {
	parts := strings.Split(s, "-")
	if len(parts) != 2 {
		return 0, serrors.New("Invalid ISD-AS", "raw", s)
	}
	isd, err := ISDFromFileFmt(parts[0], prefixes)
	if err != nil {
		return 0, err
	}
	as, err := ASFromFileFmt(parts[1], prefixes)
	if err != nil {
		return 0, err
	}
	return IAInt(isd)<<ASBits | IAInt(as&MaxAS), nil
}

func (ia *IAInt) Parse(b []byte) {
	*ia = IAInt(binary.BigEndian.Uint64(b))
}

func (ia IAInt) Write(b []byte) {
	binary.BigEndian.PutUint64(b, uint64(ia))
}

func (ia IAInt) IsZero() bool {
	return ia == 0
}

func (ia IAInt) Equal(other IAInt) bool {
	return ia == other
}

// IsWildcard returns whether the ia has a wildcard part (isd or as).
func (ia IAInt) IsWildcard() bool {
	return ia.I() == 0 || ia.A() == 0
}

func (ia IAInt) String() string {
	return fmt.Sprintf("%d-%s", ia.I(), ia.A())
}

// FileFmt returns a file-system friendly representation of ia. If prefixes is
// true, the format will be in the form of ISD%d-AS%d. If it is false, the
// format is just %d-%d.
func (ia IAInt) FileFmt(prefixes bool) string {
	fmts := "%d-%s"
	if prefixes {
		fmts = "ISD%d-AS%s"
	}
	return fmt.Sprintf(fmts, ia.I(), ia.A().FileFmt())
}

// Set implements flag.Value interface
func (ia *IAInt) Set(s string) error {
	pIA, err := IAFromString(s)
	if err != nil {
		return err
	}
	*ia = pIA
	return nil
}

func NewIAInt(isd ISD, as AS) IAInt {
	return IAInt(isd)<<ASBits | IAInt(as&MaxAS)
}
