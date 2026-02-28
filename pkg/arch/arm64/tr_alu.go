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
		// 注意：当前假设 shift type = LSL，decoder 未提取 shift type
		// 如有 ASR/LSR/ROR shifted register 会静默错误
		// 已在 decode_dp_reg.go Post 函数中添加 guard
		t.emit(vm.OpShlImm, 15, rm)
		t.emitU32(uint32(inst.Shift))
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
