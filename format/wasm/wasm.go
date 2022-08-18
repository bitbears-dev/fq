package wasm

// https://webassembly.github.io/spec/core/

import (
	"math"

	"github.com/wader/fq/format"
	"github.com/wader/fq/pkg/decode"
	"github.com/wader/fq/pkg/interp"
	"github.com/wader/fq/pkg/scalar"
)

func init() {
	interp.RegisterFormat(decode.Format{
		Name:        format.WASM,
		Description: "WebAssembly Binary Format",
		DecodeFn:    decodeWASM,
	})
}

const (
	sectionIDCustom    = 0x00
	sectionIDType      = 0x01
	sectionIDImport    = 0x02
	sectionIDFunction  = 0x03
	sectionIDTable     = 0x04
	sectionIDMemory    = 0x05
	sectionIDGlobal    = 0x06
	sectionIDExport    = 0x07
	sectionIDStart     = 0x08
	sectionIDElement   = 0x09
	sectionIDCode      = 0x0a
	sectionIDData      = 0x0b
	sectionIDDataCount = 0x0c
)

func readUnsignedLEB128(d *decode.D) scalar.S {
	var result uint64
	var shift uint

	for {
		b := d.U8()
		if shift >= 63 && b != 0 {
			d.Fatalf("overflow when reading unsigned leb128")
		}
		result |= (uint64(b&0x7f) << shift)
		if b&0x80 == 0 {
			break
		}
		shift += 7
	}
	return scalar.S{Actual: result}
}

func peekUnsignedLEB128(d *decode.D) scalar.S {
	var result uint64
	var shift uint
	n := 1

	for {
		peekedBytes := d.PeekBytes(n)
		b := peekedBytes[n-1]

		if shift >= 63 && b != 0 {
			d.Fatalf("overflow when reading unsigned leb128")
		}
		result |= (uint64(b&0x7f) << shift)
		if b&0x80 == 0 {
			break
		}
		shift += 7
		n++
	}
	return scalar.S{Actual: result}
}

func readSignedLEB128(d *decode.D) scalar.S {
	const n = 64
	var result int64
	var shift uint
	var b byte

	for {
		b = byte(d.U8())
		if shift == 63 && b != 0 && b != 0x7f {
			d.Fatalf("overflow when reading signed leb128")
		}

		result |= int64(b&0x7f) << shift
		shift += 7

		if b&0x80 == 0 {
			break
		}
	}

	if shift < n && (b&0x40) == 0x40 {
		result |= -1 << shift
	}

	return scalar.S{Actual: result}
}

func fieldU32(d *decode.D, name string) uint64 {
	n := d.FieldUScalarFn(name, readUnsignedLEB128)
	if n > math.MaxUint32 {
		d.Fatalf("invalid u32 value")
	}
	return n
}

func fieldI32(d *decode.D, name string) int64 {
	n := d.FieldSScalarFn(name, readSignedLEB128)
	if n > math.MaxInt32 || n < math.MinInt32 {
		d.Fatalf("invalid i32 value")
	}
	return n
}

func fieldI64(d *decode.D, name string) int64 {
	return d.FieldSScalarFn(name, readSignedLEB128)
}

func decodeVec(d *decode.D, fn func(d *decode.D)) {
	n := fieldU32(d, "n")
	d.FieldArray("items", func(d *decode.D) {
		for i := uint64(0); i < n; i++ {
			fn(d)
		}
	})
}

func decodeVecByte(d *decode.D) {
	n := fieldU32(d, "n")
	d.FieldRawLen("bytes", int64(n)*8)
}

func decodeTypeIdx(d *decode.D, name string) {
	fieldU32(d, name)
}

func decodeFuncIdx(d *decode.D, name string) {
	fieldU32(d, name)
}

func decodeTableIdx(d *decode.D, name string) {
	fieldU32(d, name)
}

func decodeMemIdx(d *decode.D, name string) {
	fieldU32(d, name)
}

func decodeGlobalIdx(d *decode.D, name string) {
	fieldU32(d, name)
}

func decodeElemIdx(d *decode.D, name string) {
	fieldU32(d, name)
}

func decodeDataIdx(d *decode.D, name string) {
	fieldU32(d, name)
}

func decodeLocalIdx(d *decode.D, name string) {
	fieldU32(d, name)
}

func decodeLabelIdx(d *decode.D, name string) {
	fieldU32(d, name)
}

func decodeMemArg(d *decode.D) {
	fieldU32(d, "align")
	fieldU32(d, "offset")
}

func decodeName(d *decode.D) {
	l := fieldU32(d, "len")
	if l > math.MaxInt {
		d.Fatalf("invalid length of custom section name")
	}
	d.FieldUTF8("utf8bytes", int(l))
}

func decodeResultType(d *decode.D) {
	decodeVec(d, decodeValType)
}

func decodeFuncType(d *decode.D) {
	d.FieldU8("tag", d.AssertU(0x60), scalar.ActualHex)
	d.FieldStruct("rt1", decodeResultType)
	d.FieldStruct("rt2", decodeResultType)
}

func decodeLimits(d *decode.D) {
	tag := d.FieldU8("tag", scalar.ActualHex)
	switch tag {
	case 0x00:
		fieldU32(d, "min")
	case 0x01:
		fieldU32(d, "min")
		fieldU32(d, "max")
	default:
		d.Fatalf("unknown limits type")
	}
}

func decodeImportSegment(d *decode.D) {
	d.FieldStruct("mod", decodeName)
	d.FieldStruct("nm", decodeName)
	d.FieldStruct("importdesc", decodeImportDesc)
}

func decodeImportDesc(d *decode.D) {
	tag := d.FieldU8("tag", importdescTagToSym, scalar.ActualHex)
	switch tag {
	case 0x00:
		decodeTypeIdx(d, "x")
	case 0x01:
		d.FieldStruct("tabletype", decodeTableType)
	case 0x02:
		d.FieldStruct("memtype", decodeMemType)
	case 0x03:
		d.FieldStruct("globaltype", decodeGlobalType)
	default:
		d.Fatalf("unknown import desc")
	}
}

func decodeExportDesc(d *decode.D) {
	tag := d.FieldU8("tag", exportdescTagToSym, scalar.ActualHex)
	switch tag {
	case 0x00:
		decodeFuncIdx(d, "x")
	case 0x01:
		decodeTableIdx(d, "x")
	case 0x02:
		decodeMemIdx(d, "x")
	case 0x03:
		decodeGlobalIdx(d, "x")
	default:
		d.Fatalf("unknown export desc")
	}
}

func decodeBlockType(d *decode.D) {
	b := d.PeekBytes(1)[0]
	switch b {
	case 0x40:
		d.FieldU8("empty")
	case 0x6f, 0x70, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f:
		d.FieldU8("valtype", valtypeToSymMapper)
	default:
		d.FieldSScalarFn("x", readSignedLEB128)
	}
}

func decodeValType(d *decode.D) {
	d.FieldU8("valtype", valtypeToSymMapper)
}

func decodeTableType(d *decode.D) {
	decodeRefType(d)
	d.FieldStruct("limits", decodeLimits)
}

func decodeMemType(d *decode.D) {
	d.FieldStruct("limits", decodeLimits)
}

func decodeGlobalType(d *decode.D) {
	decodeValType(d)
	d.FieldU8("mut", mutToSym)
}

func decodeGlobal(d *decode.D) {
	d.FieldStruct("globaltype", decodeGlobalType)
	d.FieldStruct("expr", decodeExpr)
}

func decodeExport(d *decode.D) {
	d.FieldStruct("name", decodeName)
	d.FieldStruct("expr", decodeExportDesc)
}

func decodeStart(d *decode.D) {
	decodeFuncIdx(d, "x")
}

func decodeElem(d *decode.D) {
	tag := fieldU32(d, "tag")
	switch tag {
	case 0:
		decodeExpr(d)
		decodeVec(d, func(d *decode.D) {
			decodeFuncIdx(d, "y")
		})
	case 1, 3:
		decodeElemKind(d)
		decodeVec(d, func(d *decode.D) {
			decodeFuncIdx(d, "y")
		})
	case 2:
		decodeTableIdx(d, "x")
		decodeExpr(d)
		decodeElemKind(d)
		decodeVec(d, func(d *decode.D) {
			decodeFuncIdx(d, "y")
		})
	case 4:
		decodeExpr(d)
		decodeVec(d, decodeExpr)
	case 5, 7:
		decodeRefType(d)
		decodeVec(d, decodeExpr)
	case 6:
		decodeTableIdx(d, "x")
		decodeExpr(d)
		decodeRefType(d)
		decodeVec(d, decodeExpr)
	default:
		d.Fatalf("unknown elem type")
	}
}

func decodeElemKind(d *decode.D) {
	d.FieldU8("elemkind", d.AssertU(0x00), elemkindTagToSym)
}

func decodeRefType(d *decode.D) {
	d.FieldU8("reftype", reftypeTagToSym)
}

func decodeCode(d *decode.D) {
	size := fieldU32(d, "size")
	d.FramedFn(int64(size)*8, func(d *decode.D) {
		d.FieldStruct("code", decodeFunc)
	})
}

func decodeFunc(d *decode.D) {
	d.FieldStruct("locals", func(d *decode.D) {
		decodeVec(d, func(d *decode.D) {
			d.FieldStruct("locals", decodeLocals)
		})
	})
	d.FieldStruct("expr", decodeExpr)
}

func decodeLocals(d *decode.D) {
	fieldU32(d, "n")
	decodeValType(d)
}

func decodeDataSegment(d *decode.D) {
	tag := fieldU32(d, "tag")
	switch tag {
	case 0:
		decodeExpr(d)
		decodeVecByte(d)
	case 1:
		decodeVecByte(d)
	case 2:
		decodeMemIdx(d, "x")
		decodeExpr(d)
		decodeVecByte(d)
	default:
		d.Fatalf("unknown data segment type")
	}
}

func decodeExpr(d *decode.D) {
	d.FieldArray("instructions", func(d *decode.D) {
		for {
			b := d.PeekBytes(1)[0]
			d.FieldStruct("instr", decodeInstruction)
			if b == 0x0b {
				break
			}
		}
	})
}

func decodeCustomSection(d *decode.D) {
	d.FieldStruct("name", decodeName)
	d.FieldRawLen("bytes", d.BitsLeft())
}

func decodeTypeSection(d *decode.D) {
	decodeVec(d, func(d *decode.D) {
		d.FieldStruct("functype", decodeFuncType)
	})
}

func decodeImportSection(d *decode.D) {
	decodeVec(d, func(d *decode.D) {
		d.FieldStruct("import", decodeImportSegment)
	})
}

func decodeFunctionSection(d *decode.D) {
	decodeVec(d, func(d *decode.D) {
		decodeTypeIdx(d, "x")
	})
}

func decodeTableSection(d *decode.D) {
	decodeVec(d, func(d *decode.D) {
		d.FieldStruct("table", decodeTableType)
	})
}

func decodeMemorySection(d *decode.D) {
	decodeVec(d, func(d *decode.D) {
		d.FieldStruct("mem", decodeMemType)
	})
}

func decodeGlobalSection(d *decode.D) {
	decodeVec(d, func(d *decode.D) {
		d.FieldStruct("global", decodeGlobal)
	})
}

func decodeExportSection(d *decode.D) {
	decodeVec(d, func(d *decode.D) {
		d.FieldStruct("export", decodeExport)
	})
}

func decodeStartSection(d *decode.D) {
	d.FieldStruct("start", decodeStart)
}

func decodeElementSection(d *decode.D) {
	decodeVec(d, func(d *decode.D) {
		d.FieldStruct("elem", decodeElem)
	})
}

func decodeCodeSection(d *decode.D) {
	decodeVec(d, func(d *decode.D) {
		d.FieldStruct("code", decodeCode)
	})
}

func decodeDataSection(d *decode.D) {
	decodeVec(d, func(d *decode.D) {
		d.FieldStruct("data", decodeDataSegment)
	})
}

func decodeDataCountSection(d *decode.D) {
	d.FieldUScalarFn("count", readUnsignedLEB128)
}

func decodeWASMModule(d *decode.D) {
	d.FieldRawLen("magic", 4*8, d.AssertBitBuf([]byte("\x00asm")))
	d.FieldU32("version")
	d.FieldArray("sections", func(d *decode.D) {
		for d.BitsLeft() > 0 {
			d.FieldStruct("section", func(d *decode.D) {
				sectionID := d.FieldU8("id", sectionIDToSym)
				size := d.FieldUScalarFn("size", readUnsignedLEB128)
				if size > math.MaxInt64/8 {
					d.Fatalf("invalid section size")
				}
				d.FramedFn(int64(size)*8, func(d *decode.D) {
					switch sectionID {
					case sectionIDCustom:
						d.FieldStruct("content", decodeCustomSection)
					case sectionIDType:
						d.FieldStruct("content", decodeTypeSection)
					case sectionIDImport:
						d.FieldStruct("content", decodeImportSection)
					case sectionIDFunction:
						d.FieldStruct("content", decodeFunctionSection)
					case sectionIDTable:
						d.FieldStruct("content", decodeTableSection)
					case sectionIDMemory:
						d.FieldStruct("content", decodeMemorySection)
					case sectionIDGlobal:
						d.FieldStruct("content", decodeGlobalSection)
					case sectionIDExport:
						d.FieldStruct("content", decodeExportSection)
					case sectionIDStart:
						d.FieldStruct("content", decodeStartSection)
					case sectionIDElement:
						d.FieldStruct("element", decodeElementSection)
					case sectionIDCode:
						d.FieldStruct("content", decodeCodeSection)
					case sectionIDData:
						d.FieldStruct("content", decodeDataSection)
					case sectionIDDataCount:
						d.FieldStruct("content", decodeDataCountSection)
					default:
						d.FieldRawLen("value", d.BitsLeft())
					}
				})
			})
		}
	})
}

func decodeWASM(d *decode.D, _ any) any {
	d.Endian = decode.LittleEndian

	decodeWASMModule(d)

	return nil
}
