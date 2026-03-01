package arm64

import (
	"fmt"

	"github.com/vmpacker/pkg/vm"
)

// ============================================================
// ALU 翻译 — 算术/逻辑/移动指令
// ============================================================

func (t *Translator) trAluImm(inst vm.Instruction, vmOp byte) error {
	return t.trAluImmFlags(inst, vmOp, false)
}

func (t *Translator) trAluImmFlags(inst vm.Instruction, vmOp byte, setFlags bool) error {
	rd, err := t.mapReg(inst.Rd)
	if err != nil {
		return err
	}
	rn, err := t.mapReg(inst.Rn)
	if err != nil {
		return err
	}

	imm64 := uint64(inst.Imm)
	if imm64 > 0xFFFFFFFF {
		// 64-bit 立即数超出 u32 范围 — 用 MOV_IMM64 加载到 R15，再用 3-reg 指令
		reg3Op := immToReg3Op(vmOp)
		if reg3Op == 0 {
			return fmt.Errorf("无法将 _IMM opcode 0x%02X 映射到 3-reg 版本", vmOp)
		}
		t.emit(vm.OpMovImm, 15)
		t.emitU64(imm64)
		t.emit(reg3Op, rd, rn, 15)
	} else {
		t.emit(vmOp, rd, rn)
		t.emitU32(uint32(imm64))
	}

	if setFlags {
		// ADDS/SUBS: 在 trunc32 之前比较，确保 N flag 正确
		t.emit(vm.OpCmpImm, rd)
		t.emitU32(0)
	}
	if !inst.SF {
		t.trunc32(rd)
	}
	return nil
}

// immToReg3Op 将 _IMM opcode 映射到对应的 3-register opcode
func immToReg3Op(immOp byte) byte {
	switch immOp {
	case vm.OpAddImm:
		return vm.OpAdd
	case vm.OpSubImm:
		return vm.OpSub
	case vm.OpAndImm:
		return vm.OpAnd
	case vm.OpOrImm:
		return vm.OpOr
	case vm.OpXorImm:
		return vm.OpXor
	case vm.OpMulImm:
		return vm.OpMul
	case vm.OpShlImm:
		return vm.OpShl
	case vm.OpShrImm:
		return vm.OpShr
	case vm.OpAsrImm:
		return vm.OpAsr
	default:
		return 0
	}
}

func (t *Translator) trAluReg(inst vm.Instruction, vmOp byte) error {
	return t.trAluRegFlags(inst, vmOp, false)
}

func (t *Translator) trAluRegFlags(inst vm.Instruction, vmOp byte, setFlags bool) error {
	// ARM64 shifted-register ALU: reg 31 = XZR (not SP)
	// decoder 已标记为 REG_XZR, mapReg 映射到 R16
	// 这里需要对 Rn/Rm 为 XZR 时先清零 R16/R15
	if inst.Rn == vm.REG_XZR {
		t.emit(vm.OpMovImm32, 16) // R16 = 0
		t.emitU32(0)
	}
	if inst.Rm == vm.REG_XZR {
		t.emit(vm.OpMovImm32, 15) // R15 = 0 (用不同寄存器避免 Rn==Rm==XZR 冲突)
		t.emitU32(0)
	}

	rd, err := t.mapReg(inst.Rd)
	if err != nil {
		return err
	}
	rn, err := t.mapReg(inst.Rn)
	if err != nil {
		return err
	}
	rm, err := t.mapReg(inst.Rm)
	if err != nil {
		return err
	}

	// Rn 和 Rm 同时为 XZR 时，mapReg 都返回 16
	// 但 Rm 已经清零到 R15，所以需要修正
	if inst.Rm == vm.REG_XZR {
		rm = 15
	}

	if inst.Shift != 0 {
		// 根据 ShiftType 选择正确的移位操作
		switch inst.ShiftType {
		case 0: // LSL
			t.emit(vm.OpShlImm, 15, rm)
			t.emitU32(uint32(inst.Shift))
		case 1: // LSR
			t.emit(vm.OpShrImm, 15, rm)
			t.emitU32(uint32(inst.Shift))
		case 2: // ASR
			t.emit(vm.OpAsrImm, 15, rm)
			t.emitU32(uint32(inst.Shift))
		case 3: // ROR — 无 OpRorImm，用三地址 OpRor + 临时寄存器
			t.emit(vm.OpMovImm32, 14)
			t.emitU32(uint32(inst.Shift))
			t.emit(vm.OpRor, 15, rm, 14)
		}
		t.emit(vmOp, rd, rn, 15)
	} else {
		t.emit(vmOp, rd, rn, rm)
	}
	if setFlags {
		// ADDS/SUBS: 在 trunc32 之前比较，确保 N flag 正确
		t.emit(vm.OpCmpImm, rd)
		t.emitU32(0)
	}
	if !inst.SF {
		t.trunc32(rd)
	}
	// Rd==XZR: 结果写入 R16，等价于丢弃
	return nil
}

func (t *Translator) trMov(inst vm.Instruction) error {
	rd, err := t.mapReg(inst.Rd)
	if err != nil {
		return err
	}
	val := uint64(inst.Imm) << uint(inst.Shift)
	if val <= 0xFFFFFFFF {
		t.emit(vm.OpMovImm32, rd)
		t.emitU32(uint32(val))
	} else {
		t.emit(vm.OpMovImm, rd)
		t.emitU64(val)
	}
	return nil
}

func (t *Translator) trMovK(inst vm.Instruction) error {
	rd, err := t.mapReg(inst.Rd)
	if err != nil {
		return err
	}
	shift := uint(inst.Shift)
	val := uint64(inst.Imm) << shift
	mask := uint64(0xFFFF) << shift

	// 使用 64-bit mask 确保不破坏其他位（修复 LSL#32/48 截断）
	t.emit(vm.OpMovImm, 15)
	t.emitU64(^mask)
	t.emit(vm.OpAnd, rd, rd, 15)

	// OR in the new value
	if val <= 0xFFFFFFFF {
		t.emit(vm.OpOrImm, rd, rd)
		t.emitU32(uint32(val))
	} else {
		t.emit(vm.OpMovImm, 15)
		t.emitU64(val)
		t.emit(vm.OpOr, rd, rd, 15)
	}
	return nil
}

func (t *Translator) trMovN(inst vm.Instruction) error {
	rd, err := t.mapReg(inst.Rd)
	if err != nil {
		return err
	}
	val := ^(uint64(inst.Imm) << uint(inst.Shift))
	if val <= 0xFFFFFFFF || !inst.SF {
		t.emit(vm.OpMovImm32, rd)
		t.emitU32(uint32(val))
	} else {
		t.emit(vm.OpMovImm, rd)
		t.emitU64(val)
	}
	return nil
}

// trEON 翻译 EON: Rd = Rn XOR NOT(shift(Rm))
func (t *Translator) trEON(inst vm.Instruction) error {
	if inst.Rn == vm.REG_XZR {
		t.emit(vm.OpMovImm32, 16)
		t.emitU32(0)
	}
	if inst.Rm == vm.REG_XZR {
		t.emit(vm.OpMovImm32, 15)
		t.emitU32(0)
	}

	rd, err := t.mapReg(inst.Rd)
	if err != nil {
		return err
	}
	rn, err := t.mapReg(inst.Rn)
	if err != nil {
		return err
	}
	rm, err := t.mapReg(inst.Rm)
	if err != nil {
		return err
	}
	if inst.Rm == vm.REG_XZR {
		rm = 15
	}

	// R15 = shift(Rm)
	if inst.Shift != 0 {
		switch inst.ShiftType {
		case 0: // LSL
			t.emit(vm.OpShlImm, 15, rm)
			t.emitU32(uint32(inst.Shift))
		case 1: // LSR
			t.emit(vm.OpShrImm, 15, rm)
			t.emitU32(uint32(inst.Shift))
		case 2: // ASR
			t.emit(vm.OpAsrImm, 15, rm)
			t.emitU32(uint32(inst.Shift))
		case 3: // ROR
			t.emit(vm.OpMovImm32, 14)
			t.emitU32(uint32(inst.Shift))
			t.emit(vm.OpRor, 15, rm, 14)
		}
		rm = 15
	}
	// R15 = NOT(shift(Rm))
	t.emit(vm.OpNot, 15, rm)
	// Rd = Rn XOR R15
	t.emit(vm.OpXor, rd, rn, 15)
	if !inst.SF {
		t.trunc32(rd)
	}
	return nil
}

// trMADD 翻译 MADD/MSUB
// MADD: Rd = Ra + Rn * Rm  (isSub=false)
// MSUB: Rd = Ra - Rn * Rm  (isSub=true)
// Ra 从 inst.Raw bits[14:10] 提取
func (t *Translator) trMADD(inst vm.Instruction, isSub bool) error {
	rd, err := t.mapReg(inst.Rd)
	if err != nil {
		return err
	}
	rn, err := t.mapReg(inst.Rn)
	if err != nil {
		return err
	}
	rm, err := t.mapReg(inst.Rm)
	if err != nil {
		return err
	}
	// Ra = bits[14:10]
	raIdx := int((inst.Raw >> 10) & 0x1F)
	if raIdx == 31 {
		raIdx = vm.REG_XZR
	}
	ra, err := t.mapReg(raIdx)
	if err != nil {
		return err
	}

	// 如果 Ra 是 XZR，先清零
	if raIdx == vm.REG_XZR {
		t.emit(vm.OpMovImm32, ra)
		t.emitU32(0)
	}

	// R15 = Rn * Rm
	t.emit(vm.OpMul, 15, rn, rm)
	// Rd = Ra +/- R15
	if isSub {
		t.emit(vm.OpSub, rd, ra, 15)
	} else {
		t.emit(vm.OpAdd, rd, ra, 15)
	}
	if !inst.SF {
		t.trunc32(rd)
	}
	return nil
}

// trUmulh 翻译 UMULH Xd, Xn, Xm — 无符号高 64 位乘法
// 格式: [OpUmulh][d][n][m] = 4B
// UMULH 始终 64-bit (sf=1), 无 32-bit 变体
func (t *Translator) trUmulh(inst vm.Instruction) error {
	rd, err := t.mapReg(inst.Rd)
	if err != nil {
		return err
	}
	rn, err := t.mapReg(inst.Rn)
	if err != nil {
		return err
	}
	rm, err := t.mapReg(inst.Rm)
	if err != nil {
		return err
	}
	// Rd == XZR → 结果写入 R16, 等价于丢弃
	t.emit(vm.OpUmulh, rd, rn, rm)
	return nil
}

// trAddSubExt 翻译 ADD/SUB (extended register): Rd = Rn op extend(Rm, shift)
// option (ShiftType): 0=UXTB, 1=UXTH, 2=UXTW, 3=UXTX, 4=SXTB, 5=SXTH, 6=SXTW, 7=SXTX
// imm3 (Shift): 额外左移量 0-4
func (t *Translator) trAddSubExt(inst vm.Instruction, vmOp byte, setFlags bool) error {
	rd, err := t.mapReg(inst.Rd)
	if err != nil {
		return err
	}
	rn, err := t.mapReg(inst.Rn)
	if err != nil {
		return err
	}
	rm, err := t.mapReg(inst.Rm)
	if err != nil {
		return err
	}

	// Rn=31 在 extended register 中是 SP (decoder 未做 XZR 替换)
	// Rm 已被 decoder 做了 XZR 替换

	if inst.Rm == vm.REG_XZR {
		t.emit(vm.OpMovImm32, 15)
		t.emitU32(0)
		rm = 15
	}

	// R15 = extend(Rm)
	option := inst.ShiftType
	switch option {
	case 0: // UXTB: zero-extend byte
		t.emit(vm.OpAndImm, 15, rm)
		t.emitU32(0xFF)
	case 1: // UXTH: zero-extend halfword
		t.emit(vm.OpAndImm, 15, rm)
		t.emitU32(0xFFFF)
	case 2: // UXTW: zero-extend word
		t.emit(vm.OpAndImm, 15, rm)
		t.emitU32(0xFFFFFFFF)
	case 3: // UXTX: no extension (64-bit)
		t.emit(vm.OpMovReg, 15, rm)
	case 4: // SXTB: sign-extend byte → SHL 56, ASR 56
		t.emit(vm.OpShlImm, 15, rm)
		t.emitU32(56)
		t.emit(vm.OpAsrImm, 15, 15)
		t.emitU32(56)
	case 5: // SXTH: sign-extend halfword → SHL 48, ASR 48
		t.emit(vm.OpShlImm, 15, rm)
		t.emitU32(48)
		t.emit(vm.OpAsrImm, 15, 15)
		t.emitU32(48)
	case 6: // SXTW: sign-extend word → SHL 32, ASR 32
		t.emit(vm.OpShlImm, 15, rm)
		t.emitU32(32)
		t.emit(vm.OpAsrImm, 15, 15)
		t.emitU32(32)
	case 7: // SXTX: no extension (64-bit signed = nop)
		t.emit(vm.OpMovReg, 15, rm)
	}

	// 额外左移
	if inst.Shift > 0 {
		t.emit(vm.OpShlImm, 15, 15)
		t.emitU32(uint32(inst.Shift))
	}

	// Rd = Rn op R15
	t.emit(vmOp, rd, rn, 15)

	if setFlags {
		t.emit(vm.OpCmpImm, rd)
		t.emitU32(0)
	}
	if !inst.SF {
		t.trunc32(rd)
	}
	return nil
}

// trCCMP 翻译 CCMP/CCMN (reg/imm)
// 字节码: [op][cond][nzcv][rn][rm_or_imm5][sf] = 6B
// inst.Cond = condition, inst.WB = nzcv (default flags)
// isNeg: true=CCMN, false=CCMP
// isImm: true=imm5 variant (inst.Rm reused as imm5), false=reg variant
func (t *Translator) trCCMP(inst vm.Instruction, isNeg bool, isImm bool) error {
	rn, err := t.mapReg(inst.Rn)
	if err != nil {
		return err
	}

	var vmOp byte
	if isNeg {
		if isImm {
			vmOp = vm.OpCcmnImm
		} else {
			vmOp = vm.OpCcmnReg
		}
	} else {
		if isImm {
			vmOp = vm.OpCcmpImm
		} else {
			vmOp = vm.OpCcmpReg
		}
	}

	var rmOrImm byte
	if isImm {
		rmOrImm = byte(inst.Rm) // Rm field reused as imm5
	} else {
		rm, err := t.mapReg(inst.Rm)
		if err != nil {
			return err
		}
		rmOrImm = rm
	}

	var sf byte
	if inst.SF {
		sf = 1
	}

	t.emit(vmOp, byte(inst.Cond), byte(inst.WB), rn, rmOrImm, sf)
	return nil
}
