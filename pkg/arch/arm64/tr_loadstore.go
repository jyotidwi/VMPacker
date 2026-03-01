package arm64

import (
	"encoding/binary"

	"github.com/vmpacker/pkg/vm"
)

// ============================================================
// 加载/存储翻译 — LDR / STR / STP / LDP / LDR_REG
// ============================================================

func (t *Translator) trLoad(inst vm.Instruction) error {
	// ARM64: Rd=REG_XZR 在 LDR 上下文 = XZR (丢弃结果, decoder 已标记)
	rd, err := t.mapReg(inst.Rd)
	if err != nil {
		return err
	}
	rn, err := t.mapReg(inst.Rn)
	if err != nil {
		return err
	}

	op := Op(inst.Op)
	var vmOp byte
	switch op {
	case LDRB_IMM:
		vmOp = vm.OpLoad8
	case LDR_IMM:
		if inst.SF {
			vmOp = vm.OpLoad64
		} else {
			vmOp = vm.OpLoad32
		}
	case LDRSB_IMM:
		// LDRSB: LOAD8 + SHL 56 + ASR 56 (符号扩展 8→64)
		vmOp = vm.OpLoad8
	case LDRH_IMM:
		vmOp = vm.OpLoad16
	case LDRSH_IMM:
		// LDRSH: LOAD16 + SHL 48 + ASR 48 (符号扩展 16→64)
		vmOp = vm.OpLoad16
	case LDRSW_IMM:
		// LDRSW: LOAD32 + SHL 32 + ASR 32 (符号扩展 32→64)
		vmOp = vm.OpLoad32
	default:
		vmOp = vm.OpLoad64
	}

	// post-index: load from [Rn+0], then Rn += imm
	// pre-index:  Rn += imm first, then load from [Rn+0]
	emitWriteback := func() {
		wbImm := inst.Imm
		if wbImm >= 0 {
			t.emit(vm.OpAddImm, rn, rn)
		} else {
			t.emit(vm.OpSubImm, rn, rn)
			wbImm = -wbImm
		}
		t.emitU32(uint32(wbImm))
	}

	if inst.WB == 3 {
		// pre-index: 先更新 base, 再以 offset=0 加载
		emitWriteback()
		t.emit(vmOp, rd, rn)
		b := make([]byte, 2)
		binary.LittleEndian.PutUint16(b, 0)
		t.code = append(t.code, b...)
	} else if inst.WB == 1 {
		// post-index: 先以 offset=0 加载, 再更新 base
		t.emit(vmOp, rd, rn)
		b := make([]byte, 2)
		binary.LittleEndian.PutUint16(b, 0)
		t.code = append(t.code, b...)
		emitWriteback()
	} else {
		// unsigned/unscaled offset
		if inst.Imm < 0 {
			// LDUR/STUR 负偏移: 先计算实际地址到 R16, 再以 offset=0 加载
			tmp := byte(16)
			t.emit(vm.OpSubImm, tmp, rn)
			t.emitU32(uint32(-inst.Imm))
			t.emit(vmOp, rd, tmp)
			b := make([]byte, 2)
			binary.LittleEndian.PutUint16(b, 0)
			t.code = append(t.code, b...)
		} else {
			t.emit(vmOp, rd, rn)
			b := make([]byte, 2)
			binary.LittleEndian.PutUint16(b, uint16(inst.Imm))
			t.code = append(t.code, b...)
		}
	}

	// LDRSW: 符号扩展 32→64 (SHL 32 + ASR 32)
	if op == LDRSW_IMM {
		t.emit(vm.OpShlImm, rd, rd)
		t.emitU32(32)
		t.emit(vm.OpAsrImm, rd, rd)
		t.emitU32(32)
	}
	// LDRSB: 符号扩展 8→64 (SHL 56 + ASR 56)
	if op == LDRSB_IMM {
		t.emit(vm.OpShlImm, rd, rd)
		t.emitU32(56)
		t.emit(vm.OpAsrImm, rd, rd)
		t.emitU32(56)
	}
	// LDRSH: 符号扩展 16→64 (SHL 48 + ASR 48)
	if op == LDRSH_IMM {
		t.emit(vm.OpShlImm, rd, rd)
		t.emitU32(48)
		t.emit(vm.OpAsrImm, rd, rd)
		t.emitU32(48)
	}
	return nil
}

func (t *Translator) trStore(inst vm.Instruction) error {
	rn, err := t.mapReg(inst.Rn)
	if err != nil {
		return err
	}

	// ARM64: Rt=REG_XZR 在 STR 上下文 = XZR (零寄存器, decoder 已标记)
	rd, err2 := t.mapReg(inst.Rd)
	if err2 != nil {
		return err2
	}
	if inst.Rd == vm.REG_XZR {
		t.emit(vm.OpMovImm32, rd)
		t.emitU32(0)
	}

	op := Op(inst.Op)
	var vmOp byte
	switch op {
	case STRB_IMM:
		vmOp = vm.OpStore8
	case STR_IMM:
		if inst.SF {
			vmOp = vm.OpStore64
		} else {
			vmOp = vm.OpStore32
		}
	case STRH_IMM:
		vmOp = vm.OpStore16
	default:
		vmOp = vm.OpStore64
	}

	emitWriteback := func() {
		wbImm := inst.Imm
		if wbImm >= 0 {
			t.emit(vm.OpAddImm, rn, rn)
		} else {
			t.emit(vm.OpSubImm, rn, rn)
			wbImm = -wbImm
		}
		t.emitU32(uint32(wbImm))
	}

	if inst.WB == 3 {
		// pre-index: 先更新 base, 再以 offset=0 存储
		emitWriteback()
		t.emit(vmOp, rn, rd)
		b := make([]byte, 2)
		binary.LittleEndian.PutUint16(b, 0)
		t.code = append(t.code, b...)
	} else if inst.WB == 1 {
		// post-index: 先以 offset=0 存储, 再更新 base
		t.emit(vmOp, rn, rd)
		b := make([]byte, 2)
		binary.LittleEndian.PutUint16(b, 0)
		t.code = append(t.code, b...)
		emitWriteback()
	} else {
		// unsigned/unscaled offset
		if inst.Imm < 0 {
			// STUR 负偏移: 先计算实际地址到 R16, 再以 offset=0 存储
			tmp := byte(16)
			t.emit(vm.OpSubImm, tmp, rn)
			t.emitU32(uint32(-inst.Imm))
			t.emit(vmOp, tmp, rd)
			b := make([]byte, 2)
			binary.LittleEndian.PutUint16(b, 0)
			t.code = append(t.code, b...)
		} else {
			t.emit(vmOp, rn, rd)
			b := make([]byte, 2)
			binary.LittleEndian.PutUint16(b, uint16(inst.Imm))
			t.code = append(t.code, b...)
		}
	}

	return nil
}

func (t *Translator) trSTP(inst vm.Instruction) error {
	rn, err := t.mapReg(inst.Rn)
	if err != nil {
		return err
	}
	rt1, err := t.mapReg(inst.Rd)
	if err != nil {
		return err
	}
	rt2, err := t.mapReg(inst.Rm)
	if err != nil {
		return err
	}

	// STP: Rt/Rt2=XZR(31) → 存零值, mapReg 会映射到 R16
	// 需要先清零 R16
	if inst.Rd == vm.REG_XZR || inst.Rm == vm.REG_XZR {
		t.emit(vm.OpMovImm32, 16) // R16 = 0
		t.emitU32(0)
	}

	vmOp := vm.OpStore64
	stride := int64(8)
	if !inst.SF {
		vmOp = vm.OpStore32
		stride = 4
	}

	if inst.WB == 3 {
		if inst.Imm >= 0 {
			t.emit(vm.OpAddImm, rn, rn)
			t.emitU32(uint32(inst.Imm))
		} else {
			t.emit(vm.OpSubImm, rn, rn)
			t.emitU32(uint32(-inst.Imm))
		}
		t.emit(vmOp, rn, rt1)
		b := make([]byte, 2)
		binary.LittleEndian.PutUint16(b, 0)
		t.code = append(t.code, b...)
		t.emit(vmOp, rn, rt2)
		binary.LittleEndian.PutUint16(b, uint16(stride))
		t.code = append(t.code, b...)
	} else {
		b := make([]byte, 2)
		storeImm := inst.Imm
		if inst.WB == 1 {
			storeImm = 0 // post-index: store to [Rn+0], writeback later
		}
		binary.LittleEndian.PutUint16(b, uint16(storeImm))
		t.emit(vmOp, rn, rt1)
		t.code = append(t.code, b...)
		binary.LittleEndian.PutUint16(b, uint16(storeImm+stride))
		t.emit(vmOp, rn, rt2)
		t.code = append(t.code, b...)
		if inst.WB == 1 {
			if inst.Imm >= 0 {
				t.emit(vm.OpAddImm, rn, rn)
				t.emitU32(uint32(inst.Imm))
			} else {
				t.emit(vm.OpSubImm, rn, rn)
				t.emitU32(uint32(-inst.Imm))
			}
		}
	}

	return nil
}

func (t *Translator) trLDP(inst vm.Instruction) error {
	rn, err := t.mapReg(inst.Rn)
	if err != nil {
		return err
	}
	rt1, err := t.mapReg(inst.Rd)
	if err != nil {
		return err
	}
	rt2, err := t.mapReg(inst.Rm)
	if err != nil {
		return err
	}

	vmOp := vm.OpLoad64
	stride := int64(8)
	if !inst.SF {
		vmOp = vm.OpLoad32
		stride = 4
	}

	if inst.WB == 3 {
		if inst.Imm >= 0 {
			t.emit(vm.OpAddImm, rn, rn)
			t.emitU32(uint32(inst.Imm))
		} else {
			t.emit(vm.OpSubImm, rn, rn)
			t.emitU32(uint32(-inst.Imm))
		}
		t.emit(vmOp, rt1, rn)
		b := make([]byte, 2)
		binary.LittleEndian.PutUint16(b, 0)
		t.code = append(t.code, b...)
		t.emit(vmOp, rt2, rn)
		binary.LittleEndian.PutUint16(b, uint16(stride))
		t.code = append(t.code, b...)
	} else {
		b := make([]byte, 2)
		loadImm := inst.Imm
		if inst.WB == 1 {
			loadImm = 0 // post-index: load from [Rn+0], writeback later
		}
		// 当 rt1 == rn 时, 第一个 load 会覆写基地址寄存器
		// ARM64 LDP 是原子操作, 两个 load 共用原始基地址
		// 需要先保存 rn 到 R15 临时寄存器
		baseReg := rn
		if rt1 == rn {
			t.emit(vm.OpMovReg, 15, rn) // R15 = Rn (保存基地址)
			baseReg = 15
		}
		binary.LittleEndian.PutUint16(b, uint16(loadImm))
		t.emit(vmOp, rt1, baseReg)
		t.code = append(t.code, b...)
		binary.LittleEndian.PutUint16(b, uint16(loadImm+stride))
		t.emit(vmOp, rt2, baseReg)
		t.code = append(t.code, b...)
		if inst.WB == 1 {
			if inst.Imm >= 0 {
				t.emit(vm.OpAddImm, rn, rn)
				t.emitU32(uint32(inst.Imm))
			} else {
				t.emit(vm.OpSubImm, rn, rn)
				t.emitU32(uint32(-inst.Imm))
			}
		}
	}

	return nil
}

func (t *Translator) trLoadReg(inst vm.Instruction) error {
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

	option := (inst.Raw >> 13) & 7
	s := (inst.Raw >> 12) & 1
	size := (inst.Raw >> 30) & 3

	shift := uint32(0)
	_ = option
	if s == 1 {
		shift = size
	}

	tmp := byte(15)
	if shift > 0 {
		t.emit(vm.OpShlImm, tmp, rm)
		t.emitU32(shift)
		t.emit(vm.OpAdd, tmp, rn, tmp)
	} else {
		t.emit(vm.OpAdd, tmp, rn, rm)
	}

	op := Op(inst.Op)
	var vmOp byte
	switch {
	case op == LDRB_REG:
		vmOp = vm.OpLoad8
	case inst.SF:
		vmOp = vm.OpLoad64
	default:
		vmOp = vm.OpLoad32
	}

	t.emit(vmOp, rd, tmp)
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, 0)
	t.code = append(t.code, b...)
	return nil
}

func (t *Translator) trStoreReg(inst vm.Instruction) error {
	rn, err := t.mapReg(inst.Rn)
	if err != nil {
		return err
	}
	rd, err := t.mapReg(inst.Rd) // Rt (source register for store)
	if err != nil {
		return err
	}
	rm, err := t.mapReg(inst.Rm)
	if err != nil {
		return err
	}

	option := (inst.Raw >> 13) & 7
	s := (inst.Raw >> 12) & 1
	size := (inst.Raw >> 30) & 3

	shift := uint32(0)
	_ = option
	if s == 1 {
		shift = size
	}

	tmp := byte(15)
	if shift > 0 {
		t.emit(vm.OpShlImm, tmp, rm)
		t.emitU32(shift)
		t.emit(vm.OpAdd, tmp, rn, tmp)
	} else {
		t.emit(vm.OpAdd, tmp, rn, rm)
	}

	op := Op(inst.Op)
	var vmOp byte
	switch {
	case op == STRB_REG:
		vmOp = vm.OpStore8
	case inst.SF:
		vmOp = vm.OpStore64
	default:
		vmOp = vm.OpStore32
	}

	t.emit(vmOp, tmp, rd)
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, 0)
	t.code = append(t.code, b...)
	return nil
}

// trLdrLiteral 翻译 LDR literal (PC-relative) 指令
// ARM64: LDR Xt/Wt, [PC + imm19*4]
// VM:   MOV_IMM64 tmp, abs_addr; LOAD Rd, tmp, 0
//
//	(LDRSW: 再做 SHL+ASR 符号扩展)
func (t *Translator) trLdrLiteral(inst vm.Instruction) error {
	rd, err := t.mapReg(inst.Rd)
	if err != nil {
		return err
	}

	// 计算绝对目标地址:
	// PC = funcAddr + inst.Offset
	// target = PC + imm (imm already = imm19*4 from postLdrLiteral)
	absAddr := t.funcAddr + uint64(inst.Offset) + uint64(inst.Imm)

	// 使用临时寄存器保存地址
	tmp := byte(16) // R16 = XZR/临时寄存器

	// MOV_IMM64 tmp, absAddr
	t.emit(vm.OpMovImm, tmp)
	ab := make([]byte, 8)
	binary.LittleEndian.PutUint64(ab, absAddr)
	t.code = append(t.code, ab...)

	// 选择 LOAD 宽度
	isLDRSW := (inst.WB == 4) // postLdrLiteral 用 WB=4 标记 LDRSW
	var vmOp byte
	if isLDRSW {
		vmOp = vm.OpLoad32 // 先加载 32-bit，后面再符号扩展
	} else if inst.SF {
		vmOp = vm.OpLoad64
	} else {
		vmOp = vm.OpLoad32
	}

	// LOAD Rd, tmp, 0
	t.emit(vmOp, rd, tmp)
	lb := make([]byte, 2)
	binary.LittleEndian.PutUint16(lb, 0) // offset = 0
	t.code = append(t.code, lb...)

	// LDRSW: 32-bit → 64-bit 符号扩展 (SHL rd, rd, 32; ASR rd, rd, 32)
	if isLDRSW {
		t.emit(vm.OpShlImm, rd, rd)
		si := make([]byte, 4)
		binary.LittleEndian.PutUint32(si, 32)
		t.code = append(t.code, si...)

		t.emit(vm.OpAsrImm, rd, rd)
		binary.LittleEndian.PutUint32(si, 32)
		t.code = append(t.code, si...)
	}

	// 32-bit LDR (非 LDRSW): 截断高 32 位
	if !inst.SF && !isLDRSW {
		t.trunc32(rd)
	}

	return nil
}
