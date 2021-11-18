package interp

import (
	"io"
	"strings"

	"github.com/wader/fq/internal/gojqextra"
	"github.com/wader/fq/internal/ioextra"
	"github.com/wader/fq/pkg/ranges"
	"github.com/wader/gojq"
)

func init() {
	functionRegisterFns = append(functionRegisterFns, func(i *Interp) []Function {
		return []Function{
			{"_bits_match", 1, 2, nil, i._bitsMatch},
		}
	})
}

func (i *Interp) _bitsMatch(c interface{}, a []interface{}) gojq.Iter {
	var ok bool

	bv, err := toBufferView(c)
	if err != nil {
		return gojq.NewIter(err)
	}

	var re string
	var byteRunes bool

	switch a0 := a[0].(type) {
	case string:
		re = a0
	default:
		reBuf, err := toBytes(a0)
		if err != nil {
			return gojq.NewIter(err)
		}
		var reRs []rune
		for _, b := range reBuf {
			reRs = append(reRs, rune(b))
		}
		byteRunes = true
		re = string(reRs)
	}

	var flags string
	if len(a) > 1 {
		flags, ok = a[1].(string)
		if !ok {
			return gojq.NewIter(gojqextra.FuncTypeNameError{Name: "find", Typ: "string"})
		}
	}

	if strings.Contains(flags, "b") {
		byteRunes = true
	}

	// TODO: err to string
	// TODO: extract to regexpextra? "all" FindReaderSubmatchIndex that can iter?
	sre, err := gojqextra.CompileRegexp(re, "gimb", flags)
	if err != nil {
		return gojq.NewIter(err)
	}

	bb, err := bv.toBuffer()
	if err != nil {
		return gojq.NewIter(err)
	}

	var rr interface {
		io.RuneReader
		io.Seeker
	}
	// raw bytes regexp matching is a bit tricky, what we do is to read each byte as a codepoint (ByteRuneReader)
	// and then we can use UTF-8 encoded codepoint to match a raw byte. So for example \u00ff (encoded as 0xc3 0xbf)
	// will match the byte \0xff
	if byteRunes {
		// byte mode, read each byte as a rune
		rr = ioextra.ByteRuneReader{RS: bb}
	} else {
		rr = ioextra.RuneReadSeeker{RS: bb}
	}

	var off int64
	return iterFn(func() (interface{}, bool) {
		_, err = rr.Seek(off, io.SeekStart)
		if err != nil {
			return err, false
		}

		// TODO: groups
		l := sre.FindReaderSubmatchIndex(rr)
		if l == nil {
			return nil, false
		}

		matchBitOff := (off + int64(l[0])) * 8
		bbo := BufferRange{
			bb: bv.bb,
			r: ranges.Range{
				Start: bv.r.Start + matchBitOff,
				Len:   bb.Len() - matchBitOff,
			},
			unit: 8,
		}

		off = off + int64(l[1])

		return bbo, true
	})
}