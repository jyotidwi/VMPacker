package arm64

import (
	"encoding/binary"

	"github.com/vmpacker/pkg/vm"
)

// ============================================================
// 加载/存储翻译 — LDR / STR / STP / LDP / LDR_REG
// ============================================================

func (t *Translator) trLoad(inst vm.Instruction) error {
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
	case LDRB_IMM, LDRSB_IMM:
		vmOp = vm.OpLoad8
	case LDR_IMM:
		if inst.SF {
			vmOp = vm.OpLoad64
		} else {
			vmOp = vm.OpLoad32
		}
	case LDRH_IMM, LDRSH_IMM:
		vmOp = vm.OpLoad32
	case LDRSW_IMM:
		vmOp = vm.OpLoad32
	default:
		vmOp = vm.OpLoad64
	}

	// post-index: load from [Rn+0], then Rn += imm
	// pre-index:  load from [Rn+imm], then Rn += imm
	loadImm := inst.Imm
	if inst.WB == 1 { // post-index
		loadImm = 0
	}

	imm16 := uint16(loadImm)
	t.emit(vmOp, rd, rn)
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, imm16)
	t.code = append(t.code, b...)

	// writeback: update base register (ALU_IMM = 7B: op|d|n|imm32)
	if inst.WB != 0 {
		wbImm := inst.Imm
		if wbImm >= 0 {
			t.emit(vm.OpAddImm, rn, rn)
		} else {
			t.emit(vm.OpSubImm, rn, rn)
			wbImm = -wbImm
		}
		t.emitU32(uint32(wbImm))
	}
	return nil
}

func (t *Translator) trStore(inst vm.Instruction) error {
	rn, err := t.mapReg(inst.Rn)
	if err != nil {
		return err
	}
	rd, err := t.mapReg(inst.Rd)
	if err != nil {
		return err
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
		vmOp = vm.OpStore32
	default:
		vmOp = vm.OpStore64
	}

	// post-index: store to [Rn+0], then Rn += imm
	// pre-index:  store to [Rn+imm], then Rn += imm
	storeImm := inst.Imm
	if inst.WB == 1 { // post-index
		storeImm = 0
	}

	imm16 := uint16(storeImm)
	t.emit(vmOp, rn, rd)
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, imm16)
	t.code = append(t.code, b...)

	// writeback: update base register (ALU_IMM = 7B: op|d|n|imm32)
	if inst.WB != 0 {
		wbImm := inst.Imm
		if wbImm >= 0 {
			t.emit(vm.OpAddImm, rn, rn)
		} else {
			t.emit(vm.OpSubImm, rn, rn)
			wbImm = -wbImm
		}
		t.emitU32(uint32(wbImm))
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
		binary.LittleEndian.PutUint16(b, uint16(inst.Imm))
		t.emit(vmOp, rn, rt1)
		t.code = append(t.code, b...)
		binary.LittleEndian.PutUint16(b, uint16(inst.Imm+stride))
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
		binary.LittleEndian.PutUint16(b, uint16(inst.Imm))
		t.emit(vmOp, rt1, rn)
		t.code = append(t.code, b...)
		binary.LittleEndian.PutUint16(b, uint16(inst.Imm+stride))
		t.emit(vmOp, rt2, rn)
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
