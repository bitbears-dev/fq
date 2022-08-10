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

func fieldU64(d *decode.D, name string) uint64 {
	return d.FieldUScalarFn(name, readUnsignedLEB128)
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

func decodeTypeIdx(d *decode.D) {
	fieldU32(d, "typeidx")
}

func decodeLabelIdx(d *decode.D) {
	fieldU32(d, "labelidx")
}

func decodeFuncIdx(d *decode.D) {
	fieldU32(d, "funcidx")
}

func decodeTableIdx(d *decode.D) {
	fieldU32(d, "tableidx")
}

func decodeMemIdx(d *decode.D) {
	fieldU32(d, "memidx")
}

func decodeLocalIdx(d *decode.D) {
	fieldU32(d, "localidx")
}

func decodeGlobalIdx(d *decode.D) {
	fieldU32(d, "globalidx")
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
		decodeTypeIdx(d)
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
		decodeFuncIdx(d)
	case 0x01:
		decodeTableIdx(d)
	case 0x02:
		decodeMemIdx(d)
	case 0x03:
		decodeGlobalIdx(d)
	default:
		d.Fatalf("unknown export desc")
	}
}

func decodeBlockType(d *decode.D) scalar.S {
	b := d.PeekBytes(1)[0]
	switch b {
	case 0x40:
		b := d.U8()
		return scalar.S{Actual: b, Sym: "empty"}
	case 0x6f, 0x70, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f:
		b := d.U8()
		s := scalar.S{Actual: b}
		mappedScalar, err := valtypeToSymMapper.MapScalar(s)
		if err != nil {
			d.Fatalf("unable to map valtype to sym")
		}
		return mappedScalar
	default:
		return readSignedLEB128(d)
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
	decodeFuncIdx(d)
}

func decodeElem(d *decode.D) {
	tag := fieldU32(d, "tag")
	switch tag {
	case 0, 4:
		decodeExpr(d)
		decodeVec(d, decodeFuncIdx)
	case 1, 3:
		decodeElemKind(d)
		decodeVec(d, decodeFuncIdx)
	case 2:
		decodeTableIdx(d)
		decodeExpr(d)
		decodeElemKind(d)
		decodeVec(d, decodeFuncIdx)
	case 5, 7:
		decodeRefType(d)
		decodeVec(d, decodeExpr)
	case 6:
		decodeTableIdx(d)
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
		decodeMemIdx(d)
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

func decodeInstruction(d *decode.D) {
	instr := d.PeekBytes(1)
	if len(instr) == 0 {
		return
	}

	switch instr[0] {
	case 0x00:
		decodeUnreachable(d)
	case 0x01:
		decodeNop(d)
	case 0x02:
		decodeBlock(d)
	case 0x03:
		decodeLoop(d)

	case 0x0b:
		decodeEnd(d)
	case 0x0c:
		decodeBr(d)
	case 0x0d:
		decodeBrIf(d)
	case 0x0e:
		decodeBrTable(d)
	case 0x0f:
		decodeReturn(d)
	case 0x10:
		decodeCall(d)
	case 0x11:
		decodeCallIndirect(d)

	case 0x1a:
		decodeDrop(d)
	case 0x1b:
		decodeSelect(d)
	case 0x1c:
		decodeSelectT(d)

	case 0x20:
		decodeLocalGet(d)
	case 0x21:
		decodeLocalSet(d)
	case 0x22:
		decodeLocalTee(d)
	case 0x23:
		decodeGlobalGet(d)
	case 0x24:
		decodeGlobalSet(d)

	case 0x28:
		decodeI32Load(d)
	case 0x29:
		decodeI64Load(d)
	case 0x2a:
		decodeF32Load(d)
	case 0x2b:
		decodeF64Load(d)
	case 0x2c:
		decodeI32Load8S(d)
	case 0x2d:
		decodeI32Load8U(d)
	case 0x2e:
		decodeI32Load16S(d)
	case 0x2f:
		decodeI32Load16U(d)
	case 0x30:
		decodeI64Load8S(d)
	case 0x31:
		decodeI64Load8U(d)
	case 0x32:
		decodeI64Load16S(d)
	case 0x33:
		decodeI64Load16U(d)
	case 0x34:
		decodeI64Load32S(d)
	case 0x35:
		decodeI64Load32U(d)
	case 0x36:
		decodeI32Store(d)
	case 0x37:
		decodeI64Store(d)
	case 0x38:
		decodeF32Store(d)
	case 0x39:
		decodeF64Store(d)
	case 0x3a:
		decodeI32Store8(d)
	case 0x3b:
		decodeI32Store16(d)
	case 0x3c:
		decodeI64Store8(d)
	case 0x3d:
		decodeI64Store16(d)
	case 0x3e:
		decodeI64Store32(d)

	case 0x3f:
		decodeMemorySize(d)
	case 0x40:
		decodeMemoryGrow(d)

	case 0x41:
		decodeI32Const(d)
	case 0x42:
		decodeI64Const(d)
	case 0x43:
		decodeF32Const(d)
	case 0x44:
		decodeF64Const(d)

	case 0x45:
		decodeI32Eqz(d)
	case 0x46:
		decodeI32Eq(d)
	case 0x47:
		decodeI32Ne(d)
	case 0x48:
		decodeI32LtS(d)
	case 0x49:
		decodeI32LtU(d)
	case 0x4a:
		decodeI32GtS(d)
	case 0x4b:
		decodeI32GtU(d)
	case 0x4c:
		decodeI32LeS(d)
	case 0x4d:
		decodeI32LeU(d)
	case 0x4e:
		decodeI32GeS(d)
	case 0x4f:
		decodeI32GeU(d)

	case 0x67:
		decodeI32Clz(d)
	case 0x68:
		decodeI32Ctz(d)
	case 0x69:
		decodeI32Popcnt(d)
	case 0x6a:
		decodeI32Add(d)
	case 0x6b:
		decodeI32Sub(d)
	case 0x6c:
		decodeI32Mul(d)
	case 0x6d:
		decodeI32DivS(d)
	case 0x6e:
		decodeI32DivU(d)
	case 0x6f:
		decodeI32RemS(d)
	case 0x70:
		decodeI32RemU(d)
	case 0x71:
		decodeI32And(d)
	case 0x72:
		decodeI32Or(d)
	case 0x73:
		decodeI32Xor(d)
	case 0x74:
		decodeI32Shl(d)
	case 0x75:
		decodeI32ShrS(d)
	case 0x76:
		decodeI32ShrU(d)
	case 0x77:
		decodeI32Rotl(d)
	case 0x78:
		decodeI32Rotr(d)
	default:
		d.Fatalf("unknown instruction: %#02x", instr[0])
	}
}

func decodeUnreachable(d *decode.D) {
	d.FieldU8("unreachable", d.AssertU(0x00), scalar.ActualHex)
}

func decodeNop(d *decode.D) {
	d.FieldU8("nop", d.AssertU(0x01), scalar.ActualHex)
}

func decodeBlock(d *decode.D) {
	d.FieldU8("block", d.AssertU(0x02), scalar.ActualHex)
	d.FieldUScalarFn("blocktype", decodeBlockType)
	d.FieldArray("instructions", func(d *decode.D) {
		for {
			b := d.PeekBytes(1)[0]
			if b == 0x0b {
				break
			}
			d.FieldStruct("instr", decodeInstruction)
		}
	})
	d.FieldU8("end", d.AssertU(0x0b))
}

func decodeLoop(d *decode.D) {
	d.FieldU8("loop", d.AssertU(0x03), scalar.ActualHex)
	d.FieldUScalarFn("blocktype", decodeBlockType)
	d.FieldArray("instructions", func(d *decode.D) {
		for {
			b := d.PeekBytes(1)[0]
			if b == 0x0b {
				break
			}
			d.FieldStruct("instr", decodeInstruction)
		}
	})
	d.FieldU8("end", d.AssertU(0x0b))
}

func decodeEnd(d *decode.D) {
	d.FieldU8("end", d.AssertU(0x0b), scalar.ActualHex)
}

func decodeBr(d *decode.D) {
	d.FieldU8("br", d.AssertU(0x0c), scalar.ActualHex)
	decodeLabelIdx(d)
}

func decodeBrIf(d *decode.D) {
	d.FieldU8("br_if", d.AssertU(0x0d), scalar.ActualHex)
	decodeLabelIdx(d)
}

func decodeBrTable(d *decode.D) {
	d.FieldU8("br_table", d.AssertU(0x0d), scalar.ActualHex)
	d.FieldStruct("table", func(d *decode.D) {
		decodeVec(d, decodeLabelIdx)
	})
	decodeLabelIdx(d)
}

func decodeReturn(d *decode.D) {
	d.FieldU8("return", d.AssertU(0x0f), scalar.ActualHex)
}

func decodeCall(d *decode.D) {
	d.FieldU8("call", d.AssertU(0x10), scalar.ActualHex)
	decodeFuncIdx(d)
}

func decodeCallIndirect(d *decode.D) {
	d.FieldU8("call", d.AssertU(0x11), scalar.ActualHex)
	decodeTypeIdx(d)
	decodeTableIdx(d)
}

func decodeDrop(d *decode.D) {
	d.FieldU8("drop", d.AssertU(0x1a), scalar.ActualHex)
}

func decodeSelect(d *decode.D) {
	d.FieldU8("select", d.AssertU(0x1b), scalar.ActualHex)
}

func decodeSelectT(d *decode.D) {
	d.FieldU8("select", d.AssertU(0x1c), scalar.ActualHex)
	decodeVec(d, func(d *decode.D) {
		decodeValType(d)
	})
}

func decodeLocalGet(d *decode.D) {
	d.FieldU8("local.get", d.AssertU(0x20), scalar.ActualHex)
	decodeLocalIdx(d)
}

func decodeLocalSet(d *decode.D) {
	d.FieldU8("local.set", d.AssertU(0x21), scalar.ActualHex)
	decodeLocalIdx(d)
}

func decodeLocalTee(d *decode.D) {
	d.FieldU8("local.tee", d.AssertU(0x22), scalar.ActualHex)
	decodeLocalIdx(d)
}

func decodeGlobalGet(d *decode.D) {
	d.FieldU8("global.get", d.AssertU(0x23), scalar.ActualHex)
	decodeGlobalIdx(d)
}

func decodeGlobalSet(d *decode.D) {
	d.FieldU8("global.set", d.AssertU(0x24), scalar.ActualHex)
	decodeGlobalIdx(d)
}

func decodeI32Load(d *decode.D) {
	d.FieldU8("i32.load", d.AssertU(0x28), scalar.ActualHex)
	decodeMemArg(d)
}

func decodeI64Load(d *decode.D) {
	d.FieldU8("i64.load", d.AssertU(0x29), scalar.ActualHex)
	decodeMemArg(d)
}

func decodeF32Load(d *decode.D) {
	d.FieldU8("f32.load", d.AssertU(0x2a), scalar.ActualHex)
	decodeMemArg(d)
}

func decodeF64Load(d *decode.D) {
	d.FieldU8("f64.load", d.AssertU(0x2b), scalar.ActualHex)
	decodeMemArg(d)
}

func decodeI32Load8S(d *decode.D) {
	d.FieldU8("i32.load8_s", d.AssertU(0x2c), scalar.ActualHex)
	decodeMemArg(d)
}

func decodeI32Load8U(d *decode.D) {
	d.FieldU8("i32.load8_u", d.AssertU(0x2d), scalar.ActualHex)
	decodeMemArg(d)
}

func decodeI32Load16S(d *decode.D) {
	d.FieldU8("i32.load16_s", d.AssertU(0x2e), scalar.ActualHex)
	decodeMemArg(d)
}

func decodeI32Load16U(d *decode.D) {
	d.FieldU8("i32.load16_u", d.AssertU(0x2f), scalar.ActualHex)
	decodeMemArg(d)
}

func decodeI64Load8S(d *decode.D) {
	d.FieldU8("i64.load8_s", d.AssertU(0x30), scalar.ActualHex)
	decodeMemArg(d)
}

func decodeI64Load8U(d *decode.D) {
	d.FieldU8("i64.load8_u", d.AssertU(0x31), scalar.ActualHex)
	decodeMemArg(d)
}

func decodeI64Load16S(d *decode.D) {
	d.FieldU8("i64.load16_s", d.AssertU(0x32), scalar.ActualHex)
	decodeMemArg(d)
}

func decodeI64Load16U(d *decode.D) {
	d.FieldU8("i64.load16_u", d.AssertU(0x33), scalar.ActualHex)
	decodeMemArg(d)
}

func decodeI64Load32S(d *decode.D) {
	d.FieldU8("i64.load32_s", d.AssertU(0x34), scalar.ActualHex)
	decodeMemArg(d)
}

func decodeI64Load32U(d *decode.D) {
	d.FieldU8("i64.load32_u", d.AssertU(0x35), scalar.ActualHex)
	decodeMemArg(d)
}

func decodeI32Store(d *decode.D) {
	d.FieldU8("i32.store", d.AssertU(0x36), scalar.ActualHex)
	decodeMemArg(d)
}

func decodeI64Store(d *decode.D) {
	d.FieldU8("i64.store", d.AssertU(0x37), scalar.ActualHex)
	decodeMemArg(d)
}

func decodeF32Store(d *decode.D) {
	d.FieldU8("f32.store", d.AssertU(0x38), scalar.ActualHex)
	decodeMemArg(d)
}

func decodeF64Store(d *decode.D) {
	d.FieldU8("f64.store", d.AssertU(0x39), scalar.ActualHex)
	decodeMemArg(d)
}

func decodeI32Store8(d *decode.D) {
	d.FieldU8("i32.store8", d.AssertU(0x3a), scalar.ActualHex)
	decodeMemArg(d)
}

func decodeI32Store16(d *decode.D) {
	d.FieldU8("i32.store16", d.AssertU(0x3b), scalar.ActualHex)
	decodeMemArg(d)
}

func decodeI64Store8(d *decode.D) {
	d.FieldU8("i64.store8", d.AssertU(0x3c), scalar.ActualHex)
	decodeMemArg(d)
}

func decodeI64Store16(d *decode.D) {
	d.FieldU8("i64.store16", d.AssertU(0x3d), scalar.ActualHex)
	decodeMemArg(d)
}

func decodeI64Store32(d *decode.D) {
	d.FieldU8("i64.store32", d.AssertU(0x3e), scalar.ActualHex)
	decodeMemArg(d)
}

func decodeMemorySize(d *decode.D) {
	d.FieldU8("memory.size", d.AssertU(0x3f), scalar.ActualHex)
	d.FieldU8("reserved", d.AssertU(0x00), scalar.ActualHex)
}

func decodeMemoryGrow(d *decode.D) {
	d.FieldU8("memory.grow", d.AssertU(0x40), scalar.ActualHex)
	d.FieldU8("reserved", d.AssertU(0x00), scalar.ActualHex)
}

func decodeI32Const(d *decode.D) {
	d.FieldU8("i32.const", d.AssertU(0x41), scalar.ActualHex)
	fieldU32(d, "n")
}

func decodeI64Const(d *decode.D) {
	d.FieldU8("i64.const", d.AssertU(0x42), scalar.ActualHex)
	fieldU64(d, "n")
}

func decodeF32Const(d *decode.D) {
	d.FieldU8("f32.const", d.AssertU(0x43), scalar.ActualHex)
	d.FieldF32("z")
}

func decodeF64Const(d *decode.D) {
	d.FieldU8("f64.const", d.AssertU(0x44), scalar.ActualHex)
	d.FieldF64("z")
}

func decodeI32Eqz(d *decode.D) {
	d.FieldU8("i32.eqz", d.AssertU(0x45), scalar.ActualHex)
}

func decodeI32Eq(d *decode.D) {
	d.FieldU8("i32.eq", d.AssertU(0x46), scalar.ActualHex)
}

func decodeI32Ne(d *decode.D) {
	d.FieldU8("i32.ne", d.AssertU(0x47), scalar.ActualHex)
}

func decodeI32LtS(d *decode.D) {
	d.FieldU8("i32.lt_s", d.AssertU(0x48), scalar.ActualHex)
}

func decodeI32LtU(d *decode.D) {
	d.FieldU8("i32.lt_u", d.AssertU(0x49), scalar.ActualHex)
}

func decodeI32GtS(d *decode.D) {
	d.FieldU8("i32.gt_s", d.AssertU(0x4a), scalar.ActualHex)
}

func decodeI32GtU(d *decode.D) {
	d.FieldU8("i32.gt_u", d.AssertU(0x4b), scalar.ActualHex)
}

func decodeI32LeS(d *decode.D) {
	d.FieldU8("i32.le_s", d.AssertU(0x4c), scalar.ActualHex)
}

func decodeI32LeU(d *decode.D) {
	d.FieldU8("i32.le_u", d.AssertU(0x4d), scalar.ActualHex)
}

func decodeI32GeS(d *decode.D) {
	d.FieldU8("i32.ge_s", d.AssertU(0x4e), scalar.ActualHex)
}

func decodeI32GeU(d *decode.D) {
	d.FieldU8("i32.ge_u", d.AssertU(0x4f), scalar.ActualHex)
}

func decodeI32Clz(d *decode.D) {
	d.FieldU8("i32.clz", d.AssertU(0x67), scalar.ActualHex)
}

func decodeI32Ctz(d *decode.D) {
	d.FieldU8("i32.ctz", d.AssertU(0x68), scalar.ActualHex)
}

func decodeI32Popcnt(d *decode.D) {
	d.FieldU8("i32.popcnt", d.AssertU(0x69), scalar.ActualHex)
}

func decodeI32Add(d *decode.D) {
	d.FieldU8("i32.add", d.AssertU(0x6a), scalar.ActualHex)
}

func decodeI32Sub(d *decode.D) {
	d.FieldU8("i32.sub", d.AssertU(0x6b), scalar.ActualHex)
}

func decodeI32Mul(d *decode.D) {
	d.FieldU8("i32.mul", d.AssertU(0x6c), scalar.ActualHex)
}

func decodeI32DivS(d *decode.D) {
	d.FieldU8("i32.div_s", d.AssertU(0x6d), scalar.ActualHex)
}

func decodeI32DivU(d *decode.D) {
	d.FieldU8("i32.div_u", d.AssertU(0x6e), scalar.ActualHex)
}

func decodeI32RemS(d *decode.D) {
	d.FieldU8("i32.rem_s", d.AssertU(0x6f), scalar.ActualHex)
}

func decodeI32RemU(d *decode.D) {
	d.FieldU8("i32.rem_u", d.AssertU(0x70), scalar.ActualHex)
}

func decodeI32And(d *decode.D) {
	d.FieldU8("i32.and", d.AssertU(0x71), scalar.ActualHex)
}

func decodeI32Or(d *decode.D) {
	d.FieldU8("i32.or", d.AssertU(0x72), scalar.ActualHex)
}

func decodeI32Xor(d *decode.D) {
	d.FieldU8("i32.xor", d.AssertU(0x73), scalar.ActualHex)
}

func decodeI32Shl(d *decode.D) {
	d.FieldU8("i32.shl", d.AssertU(0x74), scalar.ActualHex)
}

func decodeI32ShrS(d *decode.D) {
	d.FieldU8("i32.shr_s", d.AssertU(0x75), scalar.ActualHex)
}

func decodeI32ShrU(d *decode.D) {
	d.FieldU8("i32.shr_u", d.AssertU(0x76), scalar.ActualHex)
}

func decodeI32Rotl(d *decode.D) {
	d.FieldU8("i32.rotl", d.AssertU(0x77), scalar.ActualHex)
}

func decodeI32Rotr(d *decode.D) {
	d.FieldU8("i32.rotr", d.AssertU(0x78), scalar.ActualHex)
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
	decodeVec(d, decodeTypeIdx)
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
