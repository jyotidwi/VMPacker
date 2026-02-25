package arm64

import (
	"fmt"

	"github.com/vmpacker/pkg/vm"
)

// ============================================================
// ARM64 (AArch64) 指令解码器 v2
//
// 基于 ARM Architecture Reference Manual 的顶层分组：
//   op0[3:0] = bits[28:25]
//
// 覆盖指令:
//   数据处理（立即数/寄存器）、加载存储、分支、比较、
//   条件选择、位域、乘法、移位
// ============================================================

// Op ARM64 指令操作码
type Op int

const (
	UNKNOWN Op = iota
	ADD_IMM
	SUB_IMM
	ADDS_IMM
	SUBS_IMM
	AND_IMM
	ORR_IMM
	EOR_IMM
	MOVZ
	MOVK
	MOVN
	ADD_REG
	SUB_REG
	ADDS_REG
	SUBS_REG
	AND_REG
	ORR_REG
	EOR_REG
	ANDS_REG
	LSL_REG
	LSR_REG
	ASR_REG
	ROR_REG
	MUL
	SDIV
	UDIV
	MVN
	UBFM
	SBFM
	LDR_IMM
	LDRB_IMM
	LDRH_IMM
	LDRSB_IMM
	LDRSH_IMM
	LDRSW_IMM
	STR_IMM
	STRB_IMM
	STRH_IMM
	LDP
	STP
	LDR_LIT
	LDR_REG
	LDRB_REG
	STRB_REG
	STR_REG
	B
	BL
	BR
	BLR
	RET
	B_COND
	CBZ
	CBNZ
	TBZ
	TBNZ
	CSEL
	CSINC
	CSINV
	CSNEG
	ADR
	ADRP
	NOP
	SVC
	MADD
	MSUB
	EXTR
	LD1_16B
	ST1_16B
	UNSUPPORTED
)

// 条件码
const (
	COND_EQ = 0x0
	COND_NE = 0x1
	COND_CS = 0x2
	COND_CC = 0x3
	COND_MI = 0x4
	COND_PL = 0x5
	COND_VS = 0x6
	COND_VC = 0x7
	COND_HI = 0x8
	COND_LS = 0x9
	COND_GE = 0xA
	COND_LT = 0xB
	COND_GT = 0xC
	COND_LE = 0xD
	COND_AL = 0xE
)

// Decoder ARM64 解码器，实现 vm.Decoder 接口
type Decoder struct{}

// NewDecoder 创建 ARM64 解码器
func NewDecoder() *Decoder {
	return &Decoder{}
}

// Decode 解码一条 ARM64 指令
func (d *Decoder) Decode(raw uint32, offset int) vm.Instruction {
	inst := vm.Instruction{Raw: raw, Op: int(UNKNOWN), Offset: offset, Rd: -1, Rn: -1, Rm: -1}

	if raw == 0xD503201F {
		inst.Op = int(NOP)
		return inst
	}

	op0 := (raw >> 25) & 0xF

	switch {
	case op0>>1 == 0b100:
		decodeDataProcImm(&inst)
	case op0>>1 == 0b101:
		decodeBranchSys(&inst)
	case op0&0b0101 == 0b0100:
		decodeLoadStore(&inst)
	case op0&0b0111 == 0b0101:
		decodeDataProcReg(&inst)
	case op0 == 0b1101:
		decodeDataProcReg(&inst)
	default:
		inst.Op = int(UNSUPPORTED)
	}

	return inst
}

// InstName 返回指令名称
func (d *Decoder) InstName(op int) string {
	return OpName(Op(op))
}

// SignExtend 符号扩展
func SignExtend(val uint32, bits int) int64 {
	sign := uint32(1) << (bits - 1)
	mask := sign - 1
	if val&sign != 0 {
		return int64(int32(val | ^mask))
	}
	return int64(val & mask)
}

func decodeBitmaskImm(n, immr, imms uint32, is64 bool) (uint64, bool) {
	var regSize uint32 = 32
	if is64 {
		regSize = 64
	}
	var len_ int
	if n != 0 {
		len_ = 6
	} else {
		combined := (^imms) & 0x3F
		for len_ = 5; len_ >= 1; len_-- {
			if combined&(1<<len_) != 0 {
				break
			}
		}
		if len_ < 1 {
			return 0, false
		}
	}
	eSize := uint32(1) << len_
	if eSize > regSize {
		return 0, false
	}
	levels := eSize - 1
	s := imms & levels
	r := immr & levels
	if s == levels {
		return 0, false
	}
	welem := uint64((1 << (s + 1)) - 1)
	if r != 0 {
		welem = (welem >> r) | (welem << (eSize - r))
		welem &= (1 << eSize) - 1
	}
	var result uint64
	for pos := uint32(0); pos < regSize; pos += eSize {
		result |= welem << pos
	}
	return result, true
}

// ============================================================
// 数据处理 — 立即数
// ============================================================
func decodeDataProcImm(inst *vm.Instruction) {
	raw := inst.Raw
	op0 := (raw >> 23) & 0x7

	switch op0 {
	case 0b010, 0b011:
		sf := (raw >> 31) & 1
		op := (raw >> 30) & 1
		s := (raw >> 29) & 1
		shift := (raw >> 22) & 3
		imm12 := (raw >> 10) & 0xFFF
		rn := int((raw >> 5) & 0x1F)
		rd := int(raw & 0x1F)
		inst.Rd = rd
		inst.Rn = rn
		inst.Imm = int64(imm12)
		inst.SF = sf == 1
		if shift == 1 {
			inst.Imm <<= 12
		}
		switch {
		case op == 0 && s == 0:
			inst.Op = int(ADD_IMM)
		case op == 0 && s == 1:
			inst.Op = int(ADDS_IMM)
		case op == 1 && s == 0:
			inst.Op = int(SUB_IMM)
		case op == 1 && s == 1:
			inst.Op = int(SUBS_IMM)
		}

	case 0b100:
		sf := (raw >> 31) & 1
		opc := (raw >> 29) & 3
		n := (raw >> 22) & 1
		immr := (raw >> 16) & 0x3F
		imms := (raw >> 10) & 0x3F
		rn := int((raw >> 5) & 0x1F)
		rd := int(raw & 0x1F)
		imm, ok := decodeBitmaskImm(n, immr, imms, sf == 1)
		if !ok {
			inst.Op = int(UNSUPPORTED)
			return
		}
		inst.Rd = rd
		inst.Rn = rn
		inst.Imm = int64(imm)
		inst.SF = sf == 1
		switch opc {
		case 0b00:
			inst.Op = int(AND_IMM)
		case 0b01:
			inst.Op = int(ORR_IMM)
		case 0b10:
			inst.Op = int(EOR_IMM)
		case 0b11:
			inst.Op = int(AND_IMM)
		}

	case 0b101:
		sf := (raw >> 31) & 1
		opc := (raw >> 29) & 3
		hw := (raw >> 21) & 3
		imm16 := (raw >> 5) & 0xFFFF
		rd := int(raw & 0x1F)
		inst.Rd = rd
		inst.Imm = int64(imm16)
		inst.Shift = int(hw * 16)
		inst.SF = sf == 1
		switch opc {
		case 0b00:
			inst.Op = int(MOVN)
		case 0b10:
			inst.Op = int(MOVZ)
		case 0b11:
			inst.Op = int(MOVK)
		}

	case 0b110:
		sf := (raw >> 31) & 1
		opc := (raw >> 29) & 3
		immr := (raw >> 16) & 0x3F
		imms := (raw >> 10) & 0x3F
		rn := int((raw >> 5) & 0x1F)
		rd := int(raw & 0x1F)
		inst.Rd = rd
		inst.Rn = rn
		inst.Imm = int64(immr)
		inst.Shift = int(imms)
		inst.SF = sf == 1
		switch opc {
		case 0b00:
			inst.Op = int(SBFM)
		case 0b10:
			inst.Op = int(UBFM)
		default:
			inst.Op = int(UNSUPPORTED)
		}

	case 0b111:
		sf := (raw >> 31) & 1
		rm := int((raw >> 16) & 0x1F)
		imms := (raw >> 10) & 0x3F
		rn := int((raw >> 5) & 0x1F)
		rd := int(raw & 0x1F)
		inst.Op = int(EXTR)
		inst.Rd = rd
		inst.Rn = rn
		inst.Rm = rm
		inst.Imm = int64(imms)
		inst.SF = sf == 1

	case 0b000, 0b001:
		op := (raw >> 31) & 1
		immlo := (raw >> 29) & 3
		immhi := (raw >> 5) & 0x7FFFF
		rd := int(raw & 0x1F)
		inst.Rd = rd
		imm := int64((immhi << 2) | immlo)
		imm = SignExtend(uint32(imm), 21)
		if op == 1 {
			inst.Op = int(ADRP)
			inst.Imm = imm << 12
		} else {
			inst.Op = int(ADR)
			inst.Imm = imm
		}

	default:
		inst.Op = int(UNSUPPORTED)
	}
}

// ============================================================
// 分支 / 异常 / 系统
// ============================================================
func decodeBranchSys(inst *vm.Instruction) {
	raw := inst.Raw

	if (raw>>25)&0x7F == 0b0101010 && (raw>>24)&1 == 0 {
		cond := int(raw & 0xF)
		imm19 := (raw >> 5) & 0x7FFFF
		inst.Op = int(B_COND)
		inst.Cond = cond
		inst.Imm = SignExtend(imm19, 19) * 4
		return
	}

	if (raw>>25)&0x3F == 0b011010 {
		sf := (raw >> 31) & 1
		op := (raw >> 24) & 1
		imm19 := (raw >> 5) & 0x7FFFF
		rt := int(raw & 0x1F)
		inst.Rd = rt
		inst.Imm = SignExtend(imm19, 19) * 4
		inst.SF = sf == 1
		if op == 0 {
			inst.Op = int(CBZ)
		} else {
			inst.Op = int(CBNZ)
		}
		return
	}

	if (raw>>25)&0x3F == 0b011011 {
		op := (raw >> 24) & 1
		b5 := (raw >> 31) & 1
		b40 := (raw >> 19) & 0x1F
		imm14 := (raw >> 5) & 0x3FFF
		rt := int(raw & 0x1F)
		inst.Rd = rt
		inst.Imm = SignExtend(imm14, 14) * 4
		inst.Shift = int((b5 << 5) | b40)
		if op == 0 {
			inst.Op = int(TBZ)
		} else {
			inst.Op = int(TBNZ)
		}
		return
	}

	if (raw>>26)&0x1F == 0b00101 {
		op := (raw >> 31) & 1
		imm26 := raw & 0x3FFFFFF
		inst.Imm = SignExtend(imm26, 26) * 4
		if op == 1 {
			inst.Op = int(BL)
		} else {
			inst.Op = int(B)
		}
		return
	}

	if (raw>>25)&0x7F == 0b1101011 {
		opc := (raw >> 21) & 0xF
		rn := int((raw >> 5) & 0x1F)
		switch opc {
		case 0b0000:
			inst.Op = int(BR)
			inst.Rn = rn
		case 0b0001:
			inst.Op = int(BLR)
			inst.Rn = rn
		case 0b0010:
			inst.Op = int(RET)
			inst.Rn = rn
		default:
			inst.Op = int(UNSUPPORTED)
		}
		return
	}

	if (raw>>21)&0x7FF == 0b11010100_000 {
		inst.Op = int(SVC)
		inst.Imm = int64((raw >> 5) & 0xFFFF)
		return
	}

	inst.Op = int(UNSUPPORTED)
}

// ============================================================
// 加载/存储
// ============================================================
func decodeLoadStore(inst *vm.Instruction) {
	raw := inst.Raw

	opc := (raw >> 29) & 0x7
	v := (raw >> 26) & 1
	cat := (raw >> 23) & 0x7
	isPair := ((raw >> 27) & 0x3) == 0b01

	if isPair && v == 0 && (cat == 0b010 || cat == 0b011 || cat == 0b001) {
		l := (raw >> 22) & 1
		imm7 := (raw >> 15) & 0x7F
		rt2 := int((raw >> 10) & 0x1F)
		rn := int((raw >> 5) & 0x1F)
		rt := int(raw & 0x1F)
		sf := opc & 0x2
		offset := SignExtend(imm7, 7)
		if sf != 0 {
			offset *= 8
		} else {
			offset *= 4
		}
		inst.Rn = rn
		inst.Rd = rt
		inst.Rm = rt2
		inst.Imm = offset
		inst.SF = sf != 0
		inst.WB = int(cat)
		if l == 1 {
			inst.Op = int(LDP)
		} else {
			inst.Op = int(STP)
		}
		return
	}

	if raw&0x80000000 == 0 && (raw>>24)&0x3F == 0b001100 && (raw>>23)&1 == 0 && (raw>>16)&0x1F == 0 {
		l := (raw >> 22) & 1
		simdOp := (raw >> 12) & 0xF
		rn := int((raw >> 5) & 0x1F)
		var byteCount int64
		switch simdOp {
		case 0b0111:
			byteCount = 16
		case 0b1010:
			byteCount = 32
		case 0b0110:
			byteCount = 48
		case 0b0010:
			byteCount = 64
		default:
			return
		}
		inst.Rn = rn
		inst.Rd = int(raw & 0x1F)
		inst.Imm = byteCount
		if l == 1 {
			inst.Op = int(LD1_16B)
		} else {
			inst.Op = int(ST1_16B)
		}
		return
	}

	if (raw>>21)&0x1E1 == 0x1C1 {
		hiBits := (raw >> 10) & 3
		if hiBits == 0b10 {
			size := (raw >> 30) & 3
			loadBit := (raw >> 22) & 1
			rm := int((raw >> 16) & 0x1F)
			rn := int((raw >> 5) & 0x1F)
			rt := int(raw & 0x1F)
			inst.Rd = rt
			inst.Rn = rn
			inst.Rm = rm
			if loadBit == 1 {
				if size == 0 {
					inst.Op = int(LDRB_REG)
				} else {
					inst.Op = int(LDR_REG)
				}
			} else {
				if size == 0 {
					inst.Op = int(STRB_REG)
				} else {
					inst.Op = int(STR_REG)
				}
			}
			inst.SF = size >= 3
			return
		}
	}

	if v == 1 {
		inst.Op = int(UNSUPPORTED)
		return
	}

	// ---- Load/Store register (immediate pre/post-index) ----
	// 编码: [size:2][111][V][00][opc:2][0][imm9][wb:2][Rn:5][Rt:5]
	// wb=01 => post-index, wb=11 => pre-index
	size := (raw >> 30) & 3
	bit21 := (raw >> 21) & 1
	wbBits := (raw >> 10) & 3
	if bit21 == 0 && (wbBits == 0b01 || wbBits == 0b11) {
		imm9 := (raw >> 12) & 0x1FF
		rn := int((raw >> 5) & 0x1F)
		rt := int(raw & 0x1F)
		inst.Rd = rt
		inst.Rn = rn
		inst.Imm = SignExtend(imm9, 9)
		inst.WB = int(wbBits) // 1=post, 3=pre

		loadBit := (raw >> 22) & 1
		if loadBit == 1 {
			switch size {
			case 0:
				inst.Op = int(LDRB_IMM)
			case 1:
				inst.Op = int(LDRH_IMM)
			case 2:
				inst.Op = int(LDR_IMM)
				inst.SF = false
			default:
				inst.Op = int(LDR_IMM)
				inst.SF = true
			}
		} else {
			switch size {
			case 0:
				inst.Op = int(STRB_IMM)
			case 1:
				inst.Op = int(STRH_IMM)
			case 2:
				inst.Op = int(STR_IMM)
				inst.SF = false
			default:
				inst.Op = int(STR_IMM)
				inst.SF = true
			}
		}
		return
	}

	// ---- Load/Store register (unsigned offset imm12) ----
	// size 已在上方声明
	op2 := (raw >> 22) & 3
	imm12 := (raw >> 10) & 0xFFF
	rn := int((raw >> 5) & 0x1F)
	rt := int(raw & 0x1F)
	inst.Rd = rt
	inst.Rn = rn

	switch {
	case size == 3 && op2 == 1:
		inst.Op = int(LDR_IMM)
		inst.Imm = int64(imm12 * 8)
		inst.SF = true
	case size == 3 && op2 == 0:
		inst.Op = int(STR_IMM)
		inst.Imm = int64(imm12 * 8)
		inst.SF = true
	case size == 2 && op2 == 1:
		inst.Op = int(LDR_IMM)
		inst.Imm = int64(imm12 * 4)
		inst.SF = false
	case size == 2 && op2 == 0:
		inst.Op = int(STR_IMM)
		inst.Imm = int64(imm12 * 4)
		inst.SF = false
	case size == 0 && op2 == 1:
		inst.Op = int(LDRB_IMM)
		inst.Imm = int64(imm12)
	case size == 0 && op2 == 0:
		inst.Op = int(STRB_IMM)
		inst.Imm = int64(imm12)
	case size == 1 && op2 == 1:
		inst.Op = int(LDRH_IMM)
		inst.Imm = int64(imm12 * 2)
	case size == 1 && op2 == 0:
		inst.Op = int(STRH_IMM)
		inst.Imm = int64(imm12 * 2)
	case size == 2 && op2 == 2:
		inst.Op = int(LDRSW_IMM)
		inst.Imm = int64(imm12 * 4)
		inst.SF = true
	case size == 0 && op2 == 2:
		inst.Op = int(LDRSB_IMM)
		inst.Imm = int64(imm12)
		inst.SF = true
	case size == 0 && op2 == 3:
		inst.Op = int(LDRSB_IMM)
		inst.Imm = int64(imm12)
	case size == 1 && op2 == 2:
		inst.Op = int(LDRSH_IMM)
		inst.Imm = int64(imm12 * 2)
		inst.SF = true
	default:
		inst.Op = int(UNSUPPORTED)
	}
}

// ============================================================
// 数据处理 — 寄存器
// ============================================================
func decodeDataProcReg(inst *vm.Instruction) {
	raw := inst.Raw
	sf := (raw >> 31) & 1
	inst.SF = sf == 1

	bits2824 := (raw >> 24) & 0x1F

	if bits2824 == 0b01010 {
		opc := (raw >> 29) & 3
		n := (raw >> 21) & 1
		rm := int((raw >> 16) & 0x1F)
		imm6 := int((raw >> 10) & 0x3F)
		rn := int((raw >> 5) & 0x1F)
		rd := int(raw & 0x1F)
		inst.Rd = rd
		inst.Rn = rn
		inst.Rm = rm
		inst.Shift = imm6
		switch {
		case opc == 0b00 && n == 0:
			inst.Op = int(AND_REG)
		case opc == 0b01 && n == 0:
			inst.Op = int(ORR_REG)
		case opc == 0b01 && n == 1:
			inst.Op = int(MVN)
		case opc == 0b10 && n == 0:
			inst.Op = int(EOR_REG)
		case opc == 0b11 && n == 0:
			inst.Op = int(ANDS_REG)
		default:
			inst.Op = int(UNSUPPORTED)
		}
		return
	}

	if bits2824 == 0b01011 {
		op := (raw >> 30) & 1
		s := (raw >> 29) & 1
		rm := int((raw >> 16) & 0x1F)
		imm6 := int((raw >> 10) & 0x3F)
		rn := int((raw >> 5) & 0x1F)
		rd := int(raw & 0x1F)
		inst.Rd = rd
		inst.Rn = rn
		inst.Rm = rm
		inst.Shift = imm6
		switch {
		case op == 0 && s == 0:
			inst.Op = int(ADD_REG)
		case op == 0 && s == 1:
			inst.Op = int(ADDS_REG)
		case op == 1 && s == 0:
			inst.Op = int(SUB_REG)
		case op == 1 && s == 1:
			inst.Op = int(SUBS_REG)
		}
		return
	}

	if bits2824 == 0b11010 && (raw>>21)&1 == 0 {
		op := (raw >> 30) & 1
		rm := int((raw >> 16) & 0x1F)
		cond := int((raw >> 12) & 0xF)
		op2bits := (raw >> 10) & 3
		rn := int((raw >> 5) & 0x1F)
		rd := int(raw & 0x1F)
		inst.Rd = rd
		inst.Rn = rn
		inst.Rm = rm
		inst.Cond = cond
		switch {
		case op == 0 && op2bits == 0:
			inst.Op = int(CSEL)
		case op == 0 && op2bits == 1:
			inst.Op = int(CSINC)
		case op == 1 && op2bits == 0:
			inst.Op = int(CSINV)
		case op == 1 && op2bits == 1:
			inst.Op = int(CSNEG)
		default:
			inst.Op = int(UNSUPPORTED)
		}
		return
	}

	if bits2824 == 0b11010 && (raw>>21)&1 == 1 {
		rm := int((raw >> 16) & 0x1F)
		opcode := (raw >> 10) & 0x3F
		rn := int((raw >> 5) & 0x1F)
		rd := int(raw & 0x1F)
		inst.Rd = rd
		inst.Rn = rn
		inst.Rm = rm
		switch opcode {
		case 0b000010:
			inst.Op = int(UDIV)
		case 0b000011:
			inst.Op = int(SDIV)
		case 0b001000:
			inst.Op = int(LSL_REG)
		case 0b001001:
			inst.Op = int(LSR_REG)
		case 0b001010:
			inst.Op = int(ASR_REG)
		case 0b001011:
			inst.Op = int(ROR_REG)
		default:
			inst.Op = int(UNSUPPORTED)
		}
		return
	}

	if bits2824 == 0b11011 {
		rm := int((raw >> 16) & 0x1F)
		o0 := (raw >> 15) & 1
		ra := int((raw >> 10) & 0x1F)
		rn := int((raw >> 5) & 0x1F)
		rd := int(raw & 0x1F)
		inst.Rd = rd
		inst.Rn = rn
		inst.Rm = rm
		if o0 == 0 {
			if ra == 31 {
				inst.Op = int(MUL)
			} else {
				inst.Op = int(MADD)
			}
		} else {
			inst.Op = int(MSUB)
		}
		return
	}

	if bits2824 == 0b01011 {
		return
	}

	inst.Op = int(UNSUPPORTED)
}

// OpName 指令名称映射
func OpName(op Op) string {
	names := map[Op]string{
		ADD_IMM: "ADD(imm)", SUB_IMM: "SUB(imm)",
		ADDS_IMM: "ADDS(imm)", SUBS_IMM: "SUBS(imm)",
		AND_IMM: "AND(imm)", ORR_IMM: "ORR(imm)", EOR_IMM: "EOR(imm)",
		MOVZ: "MOVZ", MOVK: "MOVK", MOVN: "MOVN",
		UBFM: "UBFM", SBFM: "SBFM",
		ADD_REG: "ADD(reg)", SUB_REG: "SUB(reg)",
		ADDS_REG: "ADDS(reg)", SUBS_REG: "SUBS(reg)",
		AND_REG: "AND(reg)", ORR_REG: "ORR(reg)", EOR_REG: "EOR(reg)",
		ANDS_REG: "ANDS(reg)",
		LSL_REG:  "LSL(reg)", LSR_REG: "LSR(reg)",
		ASR_REG: "ASR(reg)", ROR_REG: "ROR(reg)",
		MUL: "MUL", MADD: "MADD", MSUB: "MSUB",
		SDIV: "SDIV", UDIV: "UDIV", MVN: "MVN",
		LDR_IMM: "LDR(imm)", LDRB_IMM: "LDRB(imm)", LDRH_IMM: "LDRH(imm)",
		LDRSB_IMM: "LDRSB(imm)", LDRSH_IMM: "LDRSH(imm)", LDRSW_IMM: "LDRSW(imm)",
		STR_IMM: "STR(imm)", STRB_IMM: "STRB(imm)", STRH_IMM: "STRH(imm)",
		LDR_REG: "LDR(reg)", LDRB_REG: "LDRB(reg)", STRB_REG: "STRB(reg)", STR_REG: "STR(reg)",
		LDP: "LDP", STP: "STP",
		B: "B", BL: "BL", BR: "BR", BLR: "BLR", RET: "RET",
		B_COND: "B.cond", CBZ: "CBZ", CBNZ: "CBNZ",
		TBZ: "TBZ", TBNZ: "TBNZ",
		CSEL: "CSEL", CSINC: "CSINC", CSINV: "CSINV", CSNEG: "CSNEG",
		ADR: "ADR", ADRP: "ADRP", NOP: "NOP", SVC: "SVC",
		EXTR:    "EXTR",
		LD1_16B: "LD1{16B}", ST1_16B: "ST1{16B}",
	}
	if n, ok := names[op]; ok {
		return n
	}
	return fmt.Sprintf("UNKNOWN(0x%X)", int(op))
}
